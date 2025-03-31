package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/KimMachineGun/automemlimit/memlimit"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.uber.org/automaxprocs/maxprocs"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type Config struct {
	VaultAddr        string
	S3Bucket         string
	AWSEndpoint      string
	AWSRegion        string
	RetentionDays    int
	VaultTokenPath   string
	SnapshotPath     string
	MemoryLimitRatio float64
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
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	report := BackupReport{}
	startTime := time.Now()
	defer func() {
		report.Duration = time.Since(startTime)
		if report.Success {
			log.Info().EmbedObject(report).Msg("Backup completed")
		} else {
			log.Error().EmbedObject(report).Msg("Backup failed")
		}
	}()

	if err := run(&report); err != nil {
		report.Error = err.Error()
		os.Exit(1)
	}
	report.Success = true
	os.Exit(0)
}

func run(report *BackupReport) error {
	cfg, err := LoadConfig()
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	setupSystemResources(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	vaultClient, err := setupVaultClient(cfg)
	if err != nil {
		return fmt.Errorf("vault setup: %w", err)
	}

	snapshotPath, checksum, err := createSnapshot(ctx, vaultClient, cfg)
	if err != nil {
		return fmt.Errorf("snapshot creation: %w", err)
	}
	defer secureDelete(snapshotPath)

	if fileInfo, err := os.Stat(snapshotPath); err == nil {
		report.SnapshotSize = fileInfo.Size()
	}
	report.Checksum = checksum

	awsSession, err := newAWSSession(cfg)
	if err != nil {
		return fmt.Errorf("aws session: %w", err)
	}

	if err := uploadToS3(ctx, snapshotPath, checksum, awsSession, cfg); err != nil {
		return fmt.Errorf("s3 upload: %w", err)
	}

	if err := cleanupOldSnapshots(ctx, awsSession, cfg); err != nil {
		log.Warn().Err(err).Msg("Snapshot cleanup failed")
	}

	return nil
}

func LoadConfig() (*Config, error) {
	cfg := &Config{
		VaultAddr:        getEnv("VAULT_ADDR", "http://localhost:8200"),
		S3Bucket:         requireEnv("S3BUCKET"),
		AWSEndpoint:      getEnv("AWS_ENDPOINT_URL", ""),
		AWSRegion:        getEnv("AWS_REGION", "us-west-2"),
		RetentionDays:    getEnvInt("VAULT_BACKUP_RETENTION", 7),
		VaultTokenPath:   getEnv("VAULT_TOKEN_PATH", "/vault/secrets/token"),
		SnapshotPath:     getEnv("SNAPSHOT_PATH", "/tmp"),
		MemoryLimitRatio: getEnvFloat("MEMORY_LIMIT_RATIO", 0.8),
	}

	if cfg.RetentionDays < 1 {
		return nil, errors.New("retention days must be at least 1")
	}

	return cfg, nil
}

func setupSystemResources(cfg *Config) {
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
		Str("date", date).
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
		return "", fmt.Errorf("token file: %w", err)
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
	log.Info().Str("path", snapshotPath).Str("checksum", checksum).Msg("Snapshot created")
	return snapshotPath, checksum, nil
}

func newAWSSession(cfg *Config) (*session.Session, error) {
	awsConfig := &aws.Config{
		Endpoint:         aws.String(cfg.AWSEndpoint),
		Region:           aws.String(cfg.AWSRegion),
		S3ForcePathStyle: aws.Bool(true),
	}

	// Credential handling: supports both env vars and shared config
	creds := credentials.NewChainCredentials(
		[]credentials.Provider{
			&credentials.EnvProvider{},
			&credentials.SharedCredentialsProvider{},
		},
	)

	awsConfig.Credentials = creds

	return session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config:            *awsConfig,
	})
}

func uploadToS3(ctx context.Context, path, checksum string, sess *session.Session, cfg *Config) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("file open: %w", err)
	}
	defer file.Close()

	_, err = s3.New(sess).PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket:               aws.String(cfg.S3Bucket),
		Key:                  aws.String(filepath.Base(path)),
		Body:                 file,
		ChecksumSHA256:       aws.String(checksum),
		ServerSideEncryption: aws.String("AES256"),
	})

	if err != nil {
		return fmt.Errorf("s3 put: %w", err)
	}

	log.Info().Str("bucket", cfg.S3Bucket).Str("key", filepath.Base(path)).Msg("Snapshot uploaded")
	return nil
}

func cleanupOldSnapshots(ctx context.Context, sess *session.Session, cfg *Config) error {
	cutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)
	s3Client := s3.New(sess)

	return s3Client.ListObjectsV2PagesWithContext(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(cfg.S3Bucket),
	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		for _, obj := range page.Contents {
			if obj.LastModified.Before(cutoff) && strings.HasPrefix(*obj.Key, "vaultsnapshot-") {
				if _, err := s3Client.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{
					Bucket: aws.String(cfg.S3Bucket),
					Key:    obj.Key,
				}); err != nil {
					log.Warn().Err(err).Str("key", *obj.Key).Msg("Failed to delete")
					continue
				}
				log.Info().Str("key", *obj.Key).Msg("Deleted old snapshot")
			}
		}
		return !lastPage
	})
}

func secureDelete(path string) {
	if err := os.Remove(path); err != nil {
		log.Warn().Err(err).Str("path", path).Msg("Failed to delete")
		return
	}

	if os.Getenv("SECURE_DELETE") == "true" {
		if err := overwriteFile(path); err != nil {
			log.Warn().Err(err).Str("path", path).Msg("Secure delete failed")
		}
	}
}

// Helper functions
func overwriteFile(path string) error {
	// Open file in write-only mode, truncate existing content
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	// Overwrite with random data 3 times
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
