package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
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
	AWSAccessKey    string
	AWSSecretKey    string
	PushoverAPIKey  string
	PushoverUserKey string
}

type BackupReport struct {
	Success      bool          `json:"success"`
	Duration     time.Duration `json:"duration_ms"`
	SnapshotSize int64         `json:"size_bytes"`
	Checksum     string        `json:"checksum"`
	Error        string        `json:"error,omitempty"`
}

func (r BackupReport) MarshalZerologObject(e *zerolog.Event) {
	e.Bool("success", r.Success)
	e.Dur("duration_ms", r.Duration)
	e.Int64("size_bytes", r.SnapshotSize)
	e.Str("checksum", r.Checksum)
	if r.Error != "" {
		e.Str("error", r.Error)
	}
}

func main() {
	cfg, _ := LoadConfig()

	if cfg.DebugMode {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).
			Level(zerolog.DebugLevel)
	} else {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: true}).
			Level(zerolog.InfoLevel)
	}

	report := BackupReport{}
	startTime := time.Now()
	exitCode := 0
	var pushoverAPIKey, pushoverUserKey string

	defer func() {
		if r := recover(); r != nil {
			report.Error = fmt.Sprintf("panic: %v", r)
			log.Error().
				Str("stack", string(debug.Stack())).
				Msg("Unexpected panic occurred")
			exitCode = 1
		}

		report.Duration = time.Since(startTime)
		if report.Success {
			log.Info().EmbedObject(report).Msg("Backup completed")
		} else {
			log.Error().EmbedObject(report).Msg("Backup failed")
		}

		if pushoverAPIKey != "" && pushoverUserKey != "" {
			if err := sendPushoverNotification(pushoverAPIKey, pushoverUserKey, report); err != nil {
				log.Warn().Err(err).Msg("Failed to send Pushover notification")
			}
		} else {
			log.Debug().Msg("Skipping Pushover notification - credentials not found in Vault")
		}

		if report.Error != "" {
			var errChain []string
			for unwrapped := errors.New(report.Error); unwrapped != nil; unwrapped = errors.Unwrap(unwrapped) {
				errChain = append(errChain, unwrapped.Error())
			}
			log.Error().
				Strs("error_chain", errChain).
				Msg("Failure breakdown")
		}

		os.Exit(exitCode)
	}()

	if err := run(&report, cfg, &pushoverAPIKey, &pushoverUserKey); err != nil {
		report.Error = err.Error()
		exitCode = 1
		return
	}
	report.Success = true
}

func run(report *BackupReport, cfg *Config, pushoverAPIKey, pushoverUserKey *string) error {
	setupSystemResources(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	log.Debug().Msg("Initializing Vault client")
	vaultClient, err := setupVaultClient(cfg)
	if err != nil {
		return fmt.Errorf("vault setup: %w", err)
	}
	log.Debug().Msg("Vault client initialized")

	log.Debug().Msg("Fetching credentials from Vault")
	awsAccessKey, awsSecretKey, poAPIKey, poUserKey, err := getCredentialsFromVault(vaultClient, cfg.VaultSecretPath)
	if err != nil {
		return fmt.Errorf("vault credentials: %w", err)
	}
	*pushoverAPIKey = poAPIKey
	*pushoverUserKey = poUserKey

	log.Info().Msg("Starting snapshot creation")
	snapshotPath, checksum, err := createSnapshot(ctx, vaultClient, cfg)
	if err != nil {
		return fmt.Errorf("snapshot creation: %w", err)
	}
	defer secureDelete(snapshotPath, cfg)
	log.Info().
		Str("path", snapshotPath).
		Str("checksum", checksum).
		Msg("Snapshot created")

	if fileInfo, err := os.Stat(snapshotPath); err == nil {
		report.SnapshotSize = fileInfo.Size()
		log.Debug().Int64("size_bytes", fileInfo.Size()).Msg("Snapshot file size")
	}
	report.Checksum = checksum

	log.Debug().Msg("Creating AWS session")
	awsSession, err := newAWSSession(cfg, awsAccessKey, awsSecretKey)
	if err != nil {
		return fmt.Errorf("aws session: %w", err)
	}
	log.Debug().Msg("AWS session established")

	log.Info().Msg("Starting S3 upload")
	uploadStart := time.Now()
	if err := uploadToS3(ctx, snapshotPath, checksum, awsSession, cfg); err != nil {
		return fmt.Errorf("s3 upload: %w", err)
	}
	log.Info().
		Dur("duration", time.Since(uploadStart)).
		Msg("S3 upload completed")

	log.Debug().Msg("Starting snapshot cleanup")
	snapshotsDeleted, err := cleanupOldSnapshots(ctx, awsSession, cfg)
	if err != nil {
		log.Warn().Err(err).Msg("Snapshot cleanup failed")
	} else if snapshotsDeleted {
		log.Info().Msg("Old snapshots cleaned up")
	} else {
		log.Info().Msg("No old snapshots found for cleanup")
	}

	return nil
}

func LoadConfig() (*Config, error) {
	cfg := &Config{
		VaultAddr:           getEnv("VAULT_ADDR", "http://localhost:8200"),
		S3Bucket:            requireEnv("S3BUCKET"),
		AWSEndpoint:         getEnv("AWS_ENDPOINT_URL", ""),
		AWSRegion:           getEnv("AWS_REGION", "auto"),
		RetentionDays:       getEnvInt("VAULT_BACKUP_RETENTION", 7),
		VaultKubernetesRole: getEnv("VAULT_K8S_ROLE", ""),
		VaultSecretPath:     requireEnv("VAULT_SECRET_PATH"),
		SnapshotPath:        getEnv("SNAPSHOT_PATH", "/tmp"),
		MemoryLimitRatio:    getEnvFloat("MEMORY_LIMIT_RATIO", 0.8),
		S3ChecksumAlgorithm: getEnv("S3_CHECKSUM_ALGORITHM", ""),
		DebugMode:           getEnvBool("DEBUG_MODE", false),
		SecureDelete:        getEnvBool("SECURE_DELETE", false),
	}

	if cfg.RetentionDays < 1 {
		return nil, errors.New("retention days must be at least 1")
	}

	return cfg, nil
}

func setupSystemResources(cfg *Config) {
	if cfg.DebugMode {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	if _, err := maxprocs.Set(maxprocs.Logger(log.Printf)); err != nil {
		log.Warn().Err(err).Msg("Failed to set GOMAXPROCS")
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
		log.Warn().Err(err).Msg("Failed to set memory limit")
	} else {
		log.Info().Str("limit", fmt.Sprintf("%dMB", memLimit/1024/1024)).Msg("Memory limit configured")
	}

	log.Info().
		Str("version", version).
		Str("commit", commit).
		Str("go_version", runtime.Version()).
		Msg("Starting vault-backup")
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

func createSnapshot(ctx context.Context, client *api.Client, cfg *Config) (string, string, error) {
	snapshotPath := filepath.Join(cfg.SnapshotPath, fmt.Sprintf("vaultsnapshot-%s.snap", time.Now().Format("20060102-150405")))

	file, err := os.Create(snapshotPath)
	if err != nil {
		return "", "", fmt.Errorf("file creation: %w", err)
	}
	defer file.Close()

	var h hash.Hash
	if cfg.S3ChecksumAlgorithm == "CRC32" {
		h = crc32.NewIEEE()
	} else {
		h = sha256.New()
	}

	writer := io.MultiWriter(file, h)

	if err := client.Sys().RaftSnapshotWithContext(ctx, writer); err != nil {
		os.Remove(snapshotPath)
		return "", "", fmt.Errorf("raft snapshot: %w", err)
	}

	valid, err := verifyInternalChecksums(snapshotPath)
	if err != nil || !valid {
		os.Remove(snapshotPath)
		return "", "", fmt.Errorf("internal checksum verification failed: %w", err)
	}

	checksum := fmt.Sprintf("%x", h.Sum(nil))
	return snapshotPath, checksum, nil
}

func verifyInternalChecksums(snapshotPath string) (bool, error) {
	file, err := os.Open(snapshotPath)
	if err != nil {
		return false, fmt.Errorf("failed to open snapshot: %w", err)
	}
	defer file.Close()

	tarReader := tar.NewReader(file)
	expected := make(map[string]string)

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("tar error: %w", err)
		}

		if hdr.Name == "SHA256SUMS" {
			content, _ := io.ReadAll(tarReader)
			for _, line := range strings.Split(string(content), "\n") {
				parts := strings.Fields(line)
				if len(parts) == 2 {
					expected[parts[1]] = parts[0]
				}
			}
			break
		}
	}

	if len(expected) == 0 {
		return false, fmt.Errorf("missing SHA256SUMS file")
	}

	file.Seek(0, 0)
	tarReader = tar.NewReader(file)

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("tar error: %w", err)
		}

		if hdr.Name == "SHA256SUMS" {
			continue
		}

		h := sha256.New()
		if _, err := io.Copy(h, tarReader); err != nil {
			return false, fmt.Errorf("failed to hash %s: %w", hdr.Name, err)
		}

		actual := fmt.Sprintf("%x", h.Sum(nil))
		expectedSum, exists := expected[hdr.Name]
		if !exists || actual != expectedSum {
			return false, fmt.Errorf("checksum mismatch for %s", hdr.Name)
		}
	}

	return true, nil
}

func getCredentialsFromVault(client *api.Client, secretPath string) (string, string, string, string, error) {
	secret, err := client.Logical().Read(secretPath)
	if err != nil {
		return "", "", "", "", fmt.Errorf("vault read failed: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return "", "", "", "", errors.New("no data found in vault secret")
	}

	data := secret.Data
	if v2Data, ok := data["data"].(map[string]interface{}); ok {
		data = v2Data
	}

	awsAccessKey, ok1 := data["aws_access_key"].(string)
	awsSecretKey, ok2 := data["aws_secret_key"].(string)
	if !ok1 || !ok2 {
		return "", "", "", "", errors.New("missing AWS credentials in vault secret")
	}

	poAPIKey, _ := data["pushover_api_token"].(string)
	poUserKey, _ := data["pushover_user_id"].(string)

	return awsAccessKey, awsSecretKey, poAPIKey, poUserKey, nil
}

func newAWSSession(cfg *Config, accessKey, secretKey string) (*session.Session, error) {
	awsConfig := &aws.Config{
		Endpoint:         aws.String(cfg.AWSEndpoint),
		Region:           aws.String(cfg.AWSRegion),
		S3ForcePathStyle: aws.Bool(true),
		Credentials:      credentials.NewStaticCredentials(accessKey, secretKey, ""),
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
				Str("service", r.ClientInfo.ServiceName).
				Str("operation", r.Operation.Name).
				Str("method", safeReq.Method).
				Str("path", safeReq.URL.Path).
				Msg("AWS API Request")
		})
	}

	if _, err = sess.Config.Credentials.Get(); err != nil {
		return nil, fmt.Errorf("credential validation: %w", err)
	}

	log.Debug().
		Str("region", *sess.Config.Region).
		Str("endpoint", cfg.AWSEndpoint).
		Msg("AWS session configured")

	return sess, nil
}

func uploadToS3(ctx context.Context, path, checksum string, sess *session.Session, cfg *Config) error {
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

	if cfg.S3ChecksumAlgorithm == "CRC32" {
		putObjectInput.ChecksumAlgorithm = aws.String(s3.ChecksumAlgorithmCrc32)
		checksumBytes, err := hex.DecodeString(checksum)
		if err != nil {
			return fmt.Errorf("failed to decode CRC32 checksum: %w", err)
		}
		putObjectInput.ChecksumCRC32 = aws.String(base64.StdEncoding.EncodeToString(checksumBytes))
		log.Debug().Str("algorithm", cfg.S3ChecksumAlgorithm).Msg("Using CRC32 checksum algorithm")
	} else {
		putObjectInput.ChecksumAlgorithm = aws.String(s3.ChecksumAlgorithmSha256)
		checksumBytes, err := hex.DecodeString(checksum)
		if err != nil {
			return fmt.Errorf("failed to decode SHA256 checksum: %w", err)
		}
		putObjectInput.ChecksumSHA256 = aws.String(string(checksumBytes))
		log.Debug().Str("algorithm", cfg.S3ChecksumAlgorithm).Msg("Using SHA256 checksum algorithm")
	}

	if cfg.DebugMode {
		progressTicker := time.NewTicker(15 * time.Second)
		defer progressTicker.Stop()
		done := make(chan error)

		go func() {
			_, err = s3.New(sess).PutObjectWithContext(ctx, putObjectInput)
			done <- err
		}()

		for {
			select {
			case <-progressTicker.C:
				if stats, err := file.Stat(); err == nil {
					log.Debug().
						Int64("bytes_uploaded", stats.Size()).
						Str("bucket", cfg.S3Bucket).
						Msg("Upload progress")
				}
			case err := <-done:
				if err != nil {
					return fmt.Errorf("s3 put operation: %w", err)
				}
				log.Info().Str("bucket", cfg.S3Bucket).Str("key", filepath.Base(path)).Msg("Snapshot uploaded")
				return nil
			case <-ctx.Done():
				return fmt.Errorf("upload timeout: %w", ctx.Err())
			}
		}
	}

	_, err = s3.New(sess).PutObjectWithContext(ctx, putObjectInput)
	if err != nil {
		return fmt.Errorf("s3 put operation: %w", err)
	}
	log.Info().Str("bucket", cfg.S3Bucket).Str("key", filepath.Base(path)).Msg("Snapshot uploaded")
	return nil
}

func cleanupOldSnapshots(ctx context.Context, sess *session.Session, cfg *Config) (bool, error) {
	cutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)
	s3Client := s3.New(sess)
	var snapshotsDeleted bool

	err := s3Client.ListObjectsV2PagesWithContext(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(cfg.S3Bucket),
	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, obj := range page.Contents {
			if obj.LastModified.Before(cutoff) && strings.HasPrefix(*obj.Key, "vaultsnapshot-") {
				if _, err := s3Client.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{
					Bucket: aws.String(cfg.S3Bucket),
					Key:    obj.Key,
				}); err != nil {
					log.Warn().Err(err).Str("key", *obj.Key).Msg("Delete failed")
					continue
				}
				snapshotsDeleted = true
				log.Info().Str("key", *obj.Key).Msg("Deleted old snapshot")
			}
		}
		return !lastPage
	})

	if err != nil {
		return false, err
	}

	return snapshotsDeleted, nil
}

func secureDelete(path string, cfg *Config) {
	if cfg.DebugMode {
		log.Info().Str("path", path).Msg("DEBUG_MODE: Skipping deletion")
		return
	}

	if err := os.Remove(path); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("Delete failed")
		return
	}

	if cfg.SecureDelete {
		if err := overwriteFile(path); err != nil {
			log.Warn().Err(err).Str("path", path).Msg("Secure delete failed")
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

func sendPushoverNotification(apiKey, userKey string, report BackupReport) error {
	if apiKey == "" || userKey == "" {
		return errors.New("Pushover credentials not configured")
	}
	log.Info().Msg("Sending Pushover notification")

	message := &bytes.Buffer{}
	fmt.Fprintf(message, "• Status: %s\n", map[bool]string{true: "✅ Success", false: "❌ Failed"}[report.Success])
	fmt.Fprintf(message, "• Duration: %s\n", report.Duration.Round(time.Millisecond))

	if report.Success {
		fmt.Fprintf(message, "• Size: %s\n", humanize.Bytes(uint64(report.SnapshotSize)))
		fmt.Fprintf(message, "• Checksum: %s\n", report.Checksum)
	} else if report.Error != "" {
		formattedError := strings.ReplaceAll(report.Error, ": ", "\n• ")
		fmt.Fprintf(message, "• <b>Failure Reason:</b>\n<pre>%s</pre>", formattedError)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	writer.WriteField("token", apiKey)
	writer.WriteField("user", userKey)
	writer.WriteField("title", "Vault Backup Report")
	writer.WriteField("message", message.String())
	writer.WriteField("html", "1")
	writer.WriteField("priority", map[bool]string{
		true:  "0",
		false: "1",
	}[report.Success])
	writer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.pushover.net/1/messages.json", body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pushover API error: %s (%d)", string(body), resp.StatusCode)
	}

	return nil
}
