package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
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
	VaultTokenPath      string
	SnapshotPath        string
	MemoryLimitRatio    float64
	S3ChecksumAlgorithm string
	DebugMode           bool
	PushoverAPIKey      string
	PushoverUserKey     string
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
	defer func() {
		if r := recover(); r != nil {
			report.Error = fmt.Sprintf("panic: %v", r)
			log.Error().
				Str("stack", string(debug.Stack())).
				Msg("Unexpected panic occurred")
		}

		report.Duration = time.Since(startTime)
		if report.Success {
			log.Info().EmbedObject(report).Msg("Backup completed")
		} else {
			log.Error().EmbedObject(report).Msg("Backup failed")
		}

		if err := sendPushoverNotification(cfg, report); err != nil {
			log.Warn().Err(err).Msg("Failed to send Pushover notification")
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
	}()

	if err := run(&report, cfg); err != nil {
		report.Error = err.Error()
		os.Exit(1)
	}
	report.Success = true
	os.Exit(0)
}

func run(report *BackupReport, cfg *Config) error {
	setupSystemResources(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	log.Debug().Msg("Initializing Vault client")
	vaultClient, err := setupVaultClient(cfg)
	if err != nil {
		return fmt.Errorf("vault setup: %w", err)
	}
	log.Debug().Msg("Vault client initialized")

	log.Info().Msg("Starting snapshot creation")
	snapshotPath, checksum, err := createSnapshot(ctx, vaultClient, cfg)
	if err != nil {
		return fmt.Errorf("snapshot creation: %w", err)
	}
	defer secureDelete(snapshotPath)
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
	awsSession, err := newAWSSession(cfg)
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
	if err := cleanupOldSnapshots(ctx, awsSession, cfg); err != nil {
		log.Warn().Err(err).Msg("Snapshot cleanup failed")
	} else {
		log.Info().Msg("Old snapshots cleaned up")
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
		VaultTokenPath:      getEnv("VAULT_TOKEN_PATH", "/vault/secrets/token"),
		SnapshotPath:        getEnv("SNAPSHOT_PATH", "/tmp"),
		MemoryLimitRatio:    getEnvFloat("MEMORY_LIMIT_RATIO", 0.8),
		S3ChecksumAlgorithm: getEnv("S3_CHECKSUM_ALGORITHM", ""),
		DebugMode:           getEnvBool("DEBUG_MODE", false),
		PushoverAPIKey:      getEnv("PUSHOVER_API_TOKEN", ""),
		PushoverUserKey:     getEnv("PUSHOVER_USER_KEY", ""),
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
	token, err := readVaultToken(cfg.VaultTokenPath)
	if err != nil {
		return nil, fmt.Errorf("token read: %w", err)
	}

	client, err := api.NewClient(&api.Config{
		Address:    cfg.VaultAddr,
		Timeout:    30 * time.Second,
		MaxRetries: 3,
	})
	if err != nil {
		return nil, fmt.Errorf("client creation: %w", err)
	}

	client.SetToken(token)
	return client, nil
}

func readVaultToken(path string) (string, error) {
	tokenBytes, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("token file read: %w", err)
	}
	defer func() {
		for i := range tokenBytes {
			tokenBytes[i] = 0
		}
	}()

	return strings.TrimSpace(string(tokenBytes)), nil
}

func createSnapshot(ctx context.Context, client *api.Client, cfg *Config) (string, string, error) {
	snapshotPath := filepath.Join(cfg.SnapshotPath, fmt.Sprintf("vaultsnapshot-%s.snap", time.Now().Format("20060102-150405")))

	file, err := os.OpenFile(snapshotPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", "", fmt.Errorf("file creation: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	writer := io.MultiWriter(file, hash)

	if err := client.Sys().RaftSnapshotWithContext(ctx, writer); err != nil {
		os.Remove(snapshotPath)
		return "", "", fmt.Errorf("raft snapshot: %w", err)
	}

	checksum := fmt.Sprintf("%x", hash.Sum(nil))
	return snapshotPath, checksum, nil
}

func newAWSSession(cfg *Config) (*session.Session, error) {
	awsConfig := &aws.Config{
		Endpoint:         aws.String(cfg.AWSEndpoint),
		Region:           aws.String(cfg.AWSRegion),
		S3ForcePathStyle: aws.Bool(true),
	}

	if cfg.DebugMode {
		awsConfig.LogLevel = aws.LogLevel(aws.LogDebugWithHTTPBody)
		awsConfig.Logger = aws.NewDefaultLogger()
	}

	creds := credentials.NewChainCredentials(
		[]credentials.Provider{
			&credentials.EnvProvider{},
			&credentials.SharedCredentialsProvider{
				Filename: os.Getenv("AWS_SHARED_CREDENTIALS_FILE"),
				Profile:  os.Getenv("AWS_PROFILE"),
			},
		},
	)

	awsConfig.Credentials = creds

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

	if cfg.S3ChecksumAlgorithm != "" {
		putObjectInput.ChecksumAlgorithm = aws.String(cfg.S3ChecksumAlgorithm)
		log.Debug().Str("algorithm", cfg.S3ChecksumAlgorithm).Msg("Using custom checksum algorithm")
	} else {
		putObjectInput.ChecksumSHA256 = aws.String(checksum)
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

func cleanupOldSnapshots(ctx context.Context, sess *session.Session, cfg *Config) error {
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
		return err
	}

	if snapshotsDeleted {
		log.Info().Msg("Old snapshots cleaned up")
	} else {
		log.Info().Msg("No old snapshots found for cleanup")
	}

	return nil
}

func secureDelete(path string) {
	if os.Getenv("DEBUG_MODE") == "true" {
		log.Info().Str("path", path).Msg("DEBUG_MODE: Skipping deletion")
		return
	}

	if err := os.Remove(path); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("Delete failed")
		return
	}

	if os.Getenv("SECURE_DELETE") == "true" {
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

func sendPushoverNotification(cfg *Config, report BackupReport) error {
	if cfg.PushoverAPIKey == "" || cfg.PushoverUserKey == "" {
		return errors.New("Pushover credentials not configured")
	}

	message := &bytes.Buffer{}
	fmt.Fprintf(message, "Vault Backup %s\n", map[bool]string{true: "✅ Success", false: "❌ Failed"}[report.Success])
	fmt.Fprintf(message, "• Duration: %s\n", report.Duration.Round(time.Millisecond))
	fmt.Fprintf(message, "• Size: %s\n", humanize.Bytes(uint64(report.SnapshotSize)))
	fmt.Fprintf(message, "• Checksum: %s\n", report.Checksum)

	if report.Error != "" {
		fmt.Fprintf(message, "\nErrors:\n")
		for i, errMsg := range strings.Split(report.Error, ": ") {
			fmt.Fprintf(message, "%d. %s\n", i+1, errMsg)
		}
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	writer.WriteField("token", cfg.PushoverAPIKey)
	writer.WriteField("user", cfg.PushoverUserKey)
	writer.WriteField("title", "Vault Backup Report")
	writer.WriteField("message", message.String())
	writer.WriteField("priority", map[bool]string{true: "0", false: "1"}[report.Success])
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
