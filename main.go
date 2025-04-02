package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/KimMachineGun/automemlimit/memlimit"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/dustin/go-humanize"
	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/automaxprocs/maxprocs"
)

var (
	version = "dev"
	commit  = "none"
)

func redactURL(url string) string {
	if url == "" {
		return "none"
	}
	parts := strings.SplitN(url, ".", 2)
	if len(parts) > 1 {
		return fmt.Sprintf("***.%s", parts[1])
	}
	return "***"
}

func sanitizePath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 3 {
		parts[3] = "***"
	}
	return strings.Join(parts, "/")
}

type Config struct {
	VaultAddr           string
	S3Bucket            string
	AWSEndpoint         string
	AWSRegion           string
	RetentionDays       int
	VaultKubernetesRole string
	VaultSecretPath     string
	SnapshotPath        string
	MemoryLimitRatio    float64
	S3ChecksumAlgorithm string
	DebugMode           bool
	SecureDelete        bool
}

type VaultCredentials struct {
	AWSAccess    []byte
	AWSSecret    []byte
	PushoverAPI  []byte
	PushoverUser []byte
}

type readCounter struct {
	total int64
	r     io.Reader
}

func (rc *readCounter) Read(p []byte) (n int, err error) {
	n, err = rc.r.Read(p)
	rc.total += int64(n)
	return
}

type secureString []byte

func newSecureString(b []byte) secureString {
	ss := make(secureString, len(b))
	copy(ss, b)
	zeroBytes(b)
	return ss
}

func (ss secureString) String() string {
	return string(ss)
}

func (ss *secureString) Zero() {
	if ss == nil {
		return
	}
	for i := range *ss {
		(*ss)[i] = 0
	}
	*ss = nil
}

func main() {
	cfg, _ := LoadConfig()

	if cfg.DebugMode {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:     os.Stderr,
			NoColor: true,
		})
	}

	exitCode := 0
	defer func() {
		if r := recover(); r != nil {
			log.Error().
				Str("stack", string(debug.Stack())).
				Msg(fmt.Sprintf("Unexpected panic: %v", r))
			exitCode = 1
		}
		os.Exit(exitCode)
	}()

	exitCode = run(cfg)
}

func run(cfg *Config) int {
	startTime := time.Now()
	var err error
	var snapshotSize int64
	var pushoverAPI, pushoverUser secureString
	var sendPushover bool

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
			log.Error().
				Str("stack", string(debug.Stack())).
				Msg("Panic occurred during backup")
		}

		duration := time.Since(startTime)
		success := err == nil

		if sendPushover {
			if notifyErr := sendPushoverNotification(
				pushoverAPI,
				pushoverUser,
				success,
				duration,
				snapshotSize,
				err,
			); notifyErr != nil {
				log.Warn().Err(notifyErr).Msg("Pushover notification failed")
			}
			pushoverAPI.Zero()
			pushoverUser.Zero()
		}

		if success {
			log.Info().
				Dur("duration", duration).
				Int64("size_bytes", snapshotSize).
				Msg("Backup completed")
		} else {
			log.Error().
				Err(err).
				Dur("duration", duration).
				Msg("Backup failed")

			if err != nil {
				var errChain []string
				for unwrapped := err; unwrapped != nil; unwrapped = errors.Unwrap(unwrapped) {
					errChain = append(errChain, unwrapped.Error())
				}
				log.Error().
					Strs("error_chain", errChain).
					Msg("Failure breakdown")
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Warn().Msg("Starting graceful shutdown")
		cancel()
		time.Sleep(30 * time.Second)
		os.Exit(1)
	}()

	setupSystemResources(cfg)

	log.Debug().Str("component", "vault").Msg("Initializing client")
	vaultClient, vaultErr := setupVaultClient(cfg)
	if vaultErr != nil {
		err = fmt.Errorf("vault setup: %w", vaultErr)
		return 1
	}

	log.Debug().Str("component", "credentials").Msg("Fetching from Vault")
	creds, credsErr := getCredentialsFromVault(vaultClient, cfg.VaultSecretPath)
	if credsErr != nil {
		err = fmt.Errorf("vault credentials: %w", credsErr)
		return 1
	}
	defer func() {
		zeroBytes(creds.AWSAccess)
		zeroBytes(creds.AWSSecret)
		zeroBytes(creds.PushoverAPI)
		zeroBytes(creds.PushoverUser)
	}()

	if len(creds.PushoverAPI) > 0 && len(creds.PushoverUser) > 0 {
		pushoverAPI = newSecureString(bytes.Clone(creds.PushoverAPI))
		pushoverUser = newSecureString(bytes.Clone(creds.PushoverUser))
		sendPushover = true
	}

	awsAccess := newSecureString(bytes.Clone(creds.AWSAccess))
	awsSecret := newSecureString(bytes.Clone(creds.AWSSecret))
	defer func() {
		awsAccess.Zero()
		awsSecret.Zero()
	}()

	log.Info().Str("component", "snapshot").Msg("Creation started")
	snapshotPath, snapshotErr := createSnapshot(ctx, vaultClient, cfg)
	if snapshotErr != nil {
		err = fmt.Errorf("snapshot creation: %w", snapshotErr)
		return 1
	}
	defer secureDelete(snapshotPath, cfg)

	if fileInfo, statErr := os.Stat(snapshotPath); statErr == nil {
		snapshotSize = fileInfo.Size()
	}

	log.Debug().Str("component", "aws").Msg("Creating AWS session")
	awsSession, awsErr := newAWSSession(cfg, awsAccess, awsSecret)
	if awsErr != nil {
		err = fmt.Errorf("aws session: %w", awsErr)
		return 1
	}

	log.Info().Str("component", "upload").Msg("Starting S3 upload")
	if uploadErr := uploadToS3(ctx, snapshotPath, awsSession, cfg); uploadErr != nil {
		err = fmt.Errorf("s3 upload: %w", uploadErr)
		return 1
	}

	log.Debug().Str("component", "cleanup").Msg("Starting snapshot cleanup")
	if _, cleanupErr := cleanupOldSnapshots(ctx, awsSession, cfg); cleanupErr != nil {
		log.Warn().Err(cleanupErr).Msg("Cleanup completed with errors")
	}

	return 0
}

func LoadConfig() (*Config, error) {
	cfg := &Config{
		VaultAddr:           getEnv("VAULT_ADDR", "http://localhost:8200"),
		S3Bucket:            requireEnv("S3BUCKET"),
		AWSEndpoint:         getEnv("AWS_ENDPOINT_URL", ""),
		AWSRegion:           getEnv("AWS_REGION", "auto"),
		RetentionDays:       getEnvInt("VAULT_BACKUP_RETENTION", 7),
		VaultKubernetesRole: requireEnv("VAULT_K8S_ROLE"),
		VaultSecretPath:     requireEnv("VAULT_SECRET_PATH"),
		SnapshotPath:        getEnv("SNAPSHOT_PATH", "/tmp"),
		MemoryLimitRatio:    getEnvFloat("MEMORY_LIMIT_RATIO", 0.8),
		S3ChecksumAlgorithm: getEnv("S3_CHECKSUM_ALGORITHM", ""),
		DebugMode:           getEnvBool("DEBUG_MODE", false),
		SecureDelete:        getEnvBool("SECURE_DELETE", false),
	}

	validAlgorithms := map[string]bool{
		"CRC32":  true,
		"CRC32C": true,
		"SHA1":   true,
		"SHA256": true,
		"":       true,
	}

	if !validAlgorithms[cfg.S3ChecksumAlgorithm] {
		return nil, fmt.Errorf("invalid checksum algorithm: %s. Supported: CRC32, CRC32C, SHA1, SHA256", cfg.S3ChecksumAlgorithm)
	}

	if _, err := url.ParseRequestURI(cfg.VaultAddr); err != nil {
		return nil, fmt.Errorf("invalid VAULT_ADDR: %w", err)
	}

	if cfg.AWSEndpoint != "" {
		if _, err := url.ParseRequestURI(cfg.AWSEndpoint); err != nil {
			return nil, fmt.Errorf("invalid AWS_ENDPOINT_URL: %w", err)
		}
	}

	if cfg.MemoryLimitRatio <= 0 || cfg.MemoryLimitRatio > 1 {
		return nil, errors.New("MEMORY_LIMIT_RATIO must be > 0 and ≤ 1")
	}

	if cfg.S3ChecksumAlgorithm != "" {
		allowedAlgos := map[string]bool{"CRC32": true, "SHA256": true}
		if !allowedAlgos[cfg.S3ChecksumAlgorithm] {
			return nil, fmt.Errorf("invalid S3_CHECKSUM_ALGORITHM: must be CRC32 or SHA256")
		}
	}

	if info, err := os.Stat(cfg.SnapshotPath); err != nil {
		return nil, fmt.Errorf("invalid SNAPSHOT_PATH: %w", err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("SNAPSHOT_PATH must be a directory")
	} else {
		testFile := filepath.Join(cfg.SnapshotPath, ".writetest")
		if f, err := os.Create(testFile); err != nil {
			return nil, fmt.Errorf("SNAPSHOT_PATH is not writable: %w", err)
		} else {
			f.Close()
			os.Remove(testFile)
		}
	}

	if cfg.RetentionDays < 1 {
		return nil, errors.New("retention days must be at least 1")
	}

	return cfg, nil
}

func setupSystemResources(cfg *Config) {
	log.Debug().
		Str("component", "security").
		Bool("secure_delete", cfg.SecureDelete).
		Bool("debug_mode", cfg.DebugMode).
		Float64("memory_ratio", cfg.MemoryLimitRatio).
		Msg("Security configuration")

	if _, err := maxprocs.Set(maxprocs.Logger(log.Printf)); err != nil {
		log.Warn().Str("component", "system").Err(err).Msg("Failed to set GOMAXPROCS")
	}

	memLimit, err := memlimit.SetGoMemLimitWithOpts(
		memlimit.WithProvider(
			memlimit.ApplyFallback(
				memlimit.FromCgroupHybrid,
				memlimit.FromSystem,
			),
		),
		memlimit.WithRatio(cfg.MemoryLimitRatio),
	)
	if err != nil {
		log.Warn().Str("component", "system").Err(err).Msg("Failed to set memory limit")
	} else {
		log.Info().
			Str("component", "system").
			Str("limit", fmt.Sprintf("%dMB", memLimit/1024/1024)).
			Msg("Memory configured")
	}

	log.Info().
		Str("version", version).
		Str("commit", commit).
		Str("go_version", runtime.Version()).
		Str("component", "system").
		Msg("Application starting")
}

func setupVaultClient(cfg *Config) (*api.Client, error) {
	client, err := api.NewClient(&api.Config{
		Address:    cfg.VaultAddr,
		Timeout:    30 * time.Second,
		MaxRetries: 3,
	})
	if err != nil {
		return nil, fmt.Errorf("client creation: %w", err)
	}

	saToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("failed to read service account token: %w", err)
	}

	data := map[string]interface{}{
		"role": cfg.VaultKubernetesRole,
		"jwt":  string(saToken),
	}

	resp, err := client.Logical().Write("auth/kubernetes/login", data)
	if err != nil {
		return nil, fmt.Errorf("failed to login with Kubernetes auth: %w", err)
	}
	if resp == nil || resp.Auth == nil || resp.Auth.ClientToken == "" {
		return nil, errors.New("no token returned from Kubernetes auth")
	}

	client.SetToken(resp.Auth.ClientToken)
	return client, nil
}

func createSnapshot(ctx context.Context, client *api.Client, cfg *Config) (string, error) {
	snapshotPath := filepath.Join(cfg.SnapshotPath, fmt.Sprintf("vaultsnapshot-%s.snap", time.Now().Format("20060102-150405")))

	file, err := os.Create(snapshotPath)
	if err != nil {
		return "", fmt.Errorf("file creation: %w", err)
	}
	defer file.Close()

	if err := client.Sys().RaftSnapshotWithContext(ctx, file); err != nil {
		os.Remove(snapshotPath)
		return "", fmt.Errorf("raft snapshot: %w", err)
	}

	valid, err := verifyInternalChecksums(snapshotPath)
	if err != nil || !valid {
		os.Remove(snapshotPath)
		return "", fmt.Errorf("internal checksum verification failed: %w", err)
	}

	return snapshotPath, nil
}

func verifyInternalChecksums(snapshotPath string) (bool, error) {
	log.Debug().Str("component", "validation").Msg("Starting verification")

	file, err := os.Open(snapshotPath)
	if err != nil {
		return false, fmt.Errorf("failed to open snapshot: %w", err)
	}
	defer file.Close()

	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return false, fmt.Errorf("invalid gzip format: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	expected := make(map[string]string)
	computed := make(map[string]string)

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("tar error: %w", err)
		}

		if hdr.Name == "SHA256SUMS" {
			content, err := io.ReadAll(tarReader)
			if err != nil {
				return false, fmt.Errorf("failed to read SHA256SUMS: %w", err)
			}
			expected = parseSHA256SUMS(content)
			log.Debug().
				Str("component", "validation").
				Int("files_expected", len(expected)).
				Msg("Parsed checksum file")
			break
		}
	}

	if len(expected) == 0 {
		return false, fmt.Errorf("SHA256SUMS file missing")
	}

	file.Seek(0, 0)
	gzReader, _ = gzip.NewReader(file)
	tarReader = tar.NewReader(gzReader)

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("tar error: %w", err)
		}

		if _, exists := expected[hdr.Name]; !exists {
			continue
		}

		h := sha256.New()
		if _, err := io.Copy(h, tarReader); err != nil {
			return false, fmt.Errorf("failed to hash %s: %w", hdr.Name, err)
		}
		computed[hdr.Name] = fmt.Sprintf("%x", h.Sum(nil))
	}

	for filename, expectedSum := range expected {
		actual, exists := computed[filename]
		if !exists {
			return false, fmt.Errorf("missing file %s in snapshot", filename)
		}
		if actual != expectedSum {
			return false, fmt.Errorf("checksum mismatch for %s (expected %s, got %s)",
				filename, expectedSum, actual)
		}
	}

	log.Debug().
		Str("component", "validation").
		Int("files_checked", len(computed)).
		Msg("Verification successful")
	return true, nil
}

func parseSHA256SUMS(content []byte) map[string]string {
	sums := make(map[string]string)
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 2 {
			sums[parts[1]] = parts[0]
		}
	}
	return sums
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func getCredentialsFromVault(client *api.Client, secretPath string) (VaultCredentials, error) {
	creds := VaultCredentials{}
	secret, err := client.Logical().Read(secretPath)
	if err != nil {
		return creds, fmt.Errorf("vault read failed: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return creds, errors.New("no data found in vault secret")
	}

	data := secret.Data
	if v2Data, ok := data["data"].(map[string]interface{}); ok {
		data = v2Data
	}

	if awsAccess, ok := data["aws_access_key"].(string); ok {
		creds.AWSAccess = []byte(strings.TrimSpace(awsAccess))
	}
	if awsSecret, ok := data["aws_secret_key"].(string); ok {
		creds.AWSSecret = []byte(strings.TrimSpace(awsSecret))
	}
	if len(creds.AWSAccess) == 0 || len(creds.AWSSecret) == 0 {
		return creds, errors.New("missing AWS credentials in vault secret")
	}

	if pushoverAPI, ok := data["pushover_api_token"].(string); ok {
		creds.PushoverAPI = []byte(strings.TrimSpace(pushoverAPI))
	}
	if pushoverUser, ok := data["pushover_user_id"].(string); ok {
		creds.PushoverUser = []byte(strings.TrimSpace(pushoverUser))
	}

	hasAPI := len(creds.PushoverAPI) > 0
	hasUser := len(creds.PushoverUser) > 0
	if hasAPI != hasUser {
		return creds, fmt.Errorf("partial Pushover credentials - both API token and user key required")
	}

	return creds, nil
}

func newAWSSession(cfg *Config, accessKey, secretKey secureString) (*session.Session, error) {
	accessStr := string(accessKey)
	secretStr := string(secretKey)
	defer func() {
		accessKey.Zero()
		secretKey.Zero()
	}()

	awsConfig := &aws.Config{
		Endpoint:         aws.String(cfg.AWSEndpoint),
		Region:           aws.String(cfg.AWSRegion),
		S3ForcePathStyle: aws.Bool(true),
		Credentials:      credentials.NewStaticCredentials(accessStr, secretStr, ""),
	}

	if cfg.DebugMode {
		awsConfig.LogLevel = aws.LogLevel(aws.LogDebugWithHTTPBody)
		awsConfig.Logger = aws.NewDefaultLogger()
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            *awsConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("session creation: %w", err)
	}

	if cfg.DebugMode {
		sess.Handlers.Send.PushFront(func(r *request.Request) {
			safeReq := r.HTTPRequest.Clone(r.HTTPRequest.Context())
			safeReq.Header.Del("Authorization")
			safeReq.Header.Del("X-Amz-Security-Token")

			log.Debug().
				Str("component", "aws").
				Str("service", r.ClientInfo.ServiceName).
				Str("operation", r.Operation.Name).
				Str("method", safeReq.Method).
				Str("path", sanitizePath(safeReq.URL.Path)).
				Msg("API request")
		})
	}

	if _, err = sess.Config.Credentials.Get(); err != nil {
		return nil, fmt.Errorf("credential validation: %w", err)
	}

	log.Debug().
		Str("component", "aws").
		Str("region", *sess.Config.Region).
		Str("endpoint", redactURL(cfg.AWSEndpoint)).
		Bool("encrypted", true).
		Msg("Session configured")

	return sess, nil
}

func uploadToS3(ctx context.Context, path string, sess *session.Session, cfg *Config) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("file open: %w", err)
	}
	defer file.Close()

	putObjectInput := &s3.PutObjectInput{
		Bucket:               aws.String(cfg.S3Bucket),
		Key:                  aws.String(filepath.Base(path)),
		Body:                 file,
		ServerSideEncryption: aws.String("AES256"),
	}

	switch cfg.S3ChecksumAlgorithm {
	case "CRC32":
		putObjectInput.ChecksumAlgorithm = aws.String(s3.ChecksumAlgorithmCrc32)
		log.Debug().Str("component", "upload").Msg("Using AWS CRC32 checksum")
	case "CRC32C":
		putObjectInput.ChecksumAlgorithm = aws.String(s3.ChecksumAlgorithmCrc32c)
		log.Debug().Str("component", "upload").Msg("Using AWS CRC32C checksum")
	case "SHA1":
		putObjectInput.ChecksumAlgorithm = aws.String(s3.ChecksumAlgorithmSha1)
		log.Debug().Str("component", "upload").Msg("Using AWS SHA1 checksum")
	case "SHA256":
		putObjectInput.ChecksumAlgorithm = aws.String(s3.ChecksumAlgorithmSha256)
		log.Debug().Str("component", "upload").Msg("Using AWS SHA256 checksum")
	case "":
		log.Debug().Str("component", "upload").Msg("No checksum algorithm specified, using default behavior")
	}

	svc := s3.New(sess, &aws.Config{
		Logger:   aws.NewDefaultLogger(),
		LogLevel: aws.LogLevel(aws.LogOff),
	})

	if cfg.DebugMode {
		progressTicker := time.NewTicker(15 * time.Second)
		defer progressTicker.Stop()

		done := make(chan error)
		fileInfo, _ := file.Stat()
		totalSize := fileInfo.Size()
		uploadStart := time.Now()

		go func() {
			_, err = svc.PutObjectWithContext(ctx, putObjectInput)
			done <- err
		}()

		for {
			select {
			case <-progressTicker.C:
				currentPos, _ := file.Seek(0, io.SeekCurrent)
				elapsed := time.Since(uploadStart).Seconds()
				throughput := float64(currentPos) / elapsed

				log.Debug().
					Str("component", "upload").
					Int64("bytes", currentPos).
					Int64("total", totalSize).
					Str("progress", fmt.Sprintf("%.1f%%", float64(currentPos)/float64(totalSize)*100)).
					Str("throughput", humanize.Bytes(uint64(throughput))).
					Msg("Transfer status")

			case err := <-done:
				if err != nil {
					return fmt.Errorf("s3 upload failed: %w", err)
				}
				log.Info().
					Str("component", "upload").
					Str("bucket", cfg.S3Bucket).
					Str("key", filepath.Base(path)).
					Int64("size_bytes", totalSize).
					Msg("Completed")
				return nil

			case <-ctx.Done():
				return fmt.Errorf("upload canceled: %w", ctx.Err())
			}
		}
	}

	_, err = svc.PutObjectWithContext(ctx, putObjectInput)
	if err != nil {
		return fmt.Errorf("s3 upload failed: %w", err)
	}

	log.Info().
		Str("component", "upload").
		Str("bucket", cfg.S3Bucket).
		Str("key", filepath.Base(path)).
		Msg("Completed")

	return nil
}

func cleanupOldSnapshots(ctx context.Context, sess *session.Session, cfg *Config) (int, error) {
	log.Debug().
		Str("component", "cleanup").
		Int("retention_days", cfg.RetentionDays).
		Msg("Starting cleanup")

	cutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)
	s3Client := s3.New(sess)
	var deletedCount int
	var hasError bool

	err := s3Client.ListObjectsV2PagesWithContext(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(cfg.S3Bucket),
	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		log.Debug().
			Str("component", "cleanup").
			Int("objects_in_page", len(page.Contents)).
			Msg("Processing bucket page")

		for _, obj := range page.Contents {
			if obj.LastModified == nil || obj.Key == nil {
				log.Warn().
					Str("component", "cleanup").
					Msg("Skipping invalid object metadata")
				continue
			}

			if obj.LastModified.Before(cutoff) && strings.HasPrefix(*obj.Key, "vaultsnapshot-") {
				_, delErr := s3Client.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{
					Bucket: aws.String(cfg.S3Bucket),
					Key:    obj.Key,
				})

				if delErr != nil {
					log.Warn().
						Str("component", "cleanup").
						Err(delErr).
						Str("key", *obj.Key).
						Msg("Delete failed")
					hasError = true
					continue
				}

				deletedCount++
				log.Debug().
					Str("component", "cleanup").
					Str("key", sanitizePath(*obj.Key)).
					Time("modified", *obj.LastModified).
					Msg("Deleted snapshot")
			}
		}
		return !lastPage
	})

	if err != nil {
		log.Error().
			Str("component", "cleanup").
			Err(err).
			Msg("Bucket listing failed")
		return deletedCount, fmt.Errorf("bucket listing failed: %w", err)
	}

	if hasError {
		return deletedCount, errors.New("partial deletions failed")
	}

	return deletedCount, nil
}

func secureDelete(path string, cfg *Config) {
	if cfg.DebugMode {
		log.Info().Str("path", path).Str("component", "security").Msg("Skipping deletion")
		return
	}

	if err := os.Remove(path); err != nil {
		log.Warn().Str("component", "security").Err(err).Str("path", path).Msg("Delete failed")
		return
	}

	if cfg.SecureDelete {
		if err := overwriteFile(path); err != nil {
			log.Warn().Str("component", "security").Err(err).Str("path", path).Msg("Secure delete failed")
		}
	}
}

func overwriteFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	const passes = 3
	for i := 0; i < passes; i++ {
		if _, err := f.Seek(0, 0); err != nil {
			return err
		}
		if _, err := io.CopyN(f, rand.Reader, 1<<20); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
	}
	return nil
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func requireEnv(key string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	panic(fmt.Sprintf("Required environment variable %s not set", key))
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvFloat(key string, defaultValue float64) float64 {
	if value := os.Getenv(key); value != "" {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
	}
	return defaultValue
}

func sendPushoverNotification(
	apiKey, userKey secureString,
	success bool,
	duration time.Duration,
	snapshotSize int64,
	err error,
) error {
	apiStr := string(apiKey)
	userStr := string(userKey)
	defer func() {
		apiKey.Zero()
		userKey.Zero()
	}()

	log.Debug().
		Str("token_prefix", fmt.Sprintf("%.6s", apiStr)).
		Str("user_prefix", fmt.Sprintf("%.6s", userStr)).
		Int("token_len", len(apiStr)).
		Int("user_len", len(userStr)).
		Msg("Pushover credential validation")

	if !isValidPushoverToken(apiStr) || !isValidPushoverUser(userStr) {
		return fmt.Errorf("invalid pushover credentials")
	}

	message := &bytes.Buffer{}
	statusEmoji := map[bool]string{true: "✅ Success", false: "❌ Failed"}[success]
	fmt.Fprintf(message, "• Status: %s\n", statusEmoji)
	fmt.Fprintf(message, "• Duration: %s\n", duration.Round(time.Millisecond))

	if success {
		fmt.Fprintf(message, "• Size: %s\n", humanize.Bytes(uint64(snapshotSize)))
	} else if err != nil {
		formattedError := strings.ReplaceAll(err.Error(), ": ", "\n• ")
		fmt.Fprintf(message, "• <b>Failure Reason:</b>\n<pre>%s</pre>", formattedError)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	writer.WriteField("token", apiStr)
	writer.WriteField("user", userStr)
	writer.WriteField("title", "Vault Backup Report")
	writer.WriteField("message", message.String())
	writer.WriteField("html", "1")
	writer.WriteField("priority", map[bool]string{
		true:  "0",
		false: "1",
	}[success])

	if closeErr := writer.Close(); closeErr != nil {
		return fmt.Errorf("failed to close multipart writer: %w", closeErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, reqErr := http.NewRequestWithContext(ctx, "POST",
		"https://api.pushover.net/1/messages.json", body)
	if reqErr != nil {
		return fmt.Errorf("failed to create request: %w", reqErr)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, respErr := http.DefaultClient.Do(req)
	if respErr != nil {
		return fmt.Errorf("failed to send notification: %w", respErr)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pushover API error (HTTP %d): %s",
			resp.StatusCode,
			strings.TrimSpace(string(respBody)))
	}

	return nil
}

func isValidPushoverToken(token string) bool {
	clean := strings.TrimSpace(token)
	return len(clean) == 30 && strings.HasPrefix(clean, "a")
}

func isValidPushoverUser(userKey string) bool {
	clean := strings.TrimSpace(userKey)
	return len(clean) == 30 && strings.HasPrefix(clean, "u")
}

func redactKey(key string) string {
	if len(key) < 6 {
		return "***"
	}
	return key[:1] + "***" + key[len(key)-1:]
}
