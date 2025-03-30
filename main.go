package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/hashicorp/vault/api"
	"github.com/KimMachineGun/automemlimit/memlimit"
	"go.uber.org/automaxprocs/maxprocs"
)

var (
	version = ""
	commit  = ""
	date    = ""
)

func main() {
	if err := run(); err != nil {
		log.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}

func run() error {
	setupSystemResources()

	if err := checkEnvVars(); err != nil {
		return err
	}

	vaultClient, err := setupVaultClient()
	if err != nil {
		return err
	}

	snapshotPath, err := createSnapshot(vaultClient)
	if err != nil {
		return err
	}

	awsSession, err := newAWSSession()
	if err != nil {
		return fmt.Errorf("failed to create AWS session: %w", err)
	}

	defer cleanupLocalAndRemote(snapshotPath, awsSession)

	if err := uploadToS3(snapshotPath, awsSession); err != nil {
		return err
	}

	return nil
}

func setupSystemResources() {
	_, err := maxprocs.Set(maxprocs.Logger(log.Printf))
	if err != nil {
		log.Printf("WARNING: Failed to set GOMAXPROCS: %v", err)
	}

	memLimit, err := memlimit.SetGoMemLimitWithOpts(
		memlimit.WithProvider(
			memlimit.ApplyFallback(
				memlimit.FromCgroupHybrid,
				memlimit.FromSystem,
			),
		),
	)
	if err != nil {
		log.Printf("WARNING: Failed to set GOMEMLIMIT: %v", err)
	} else {
		log.Printf("DEBUG: GOMEMLIMIT: %d bytes", memLimit)
	}

	log.Printf("INFO: Starting vault-backup (Version: %s, Commit: %s, Date: %s)", version, commit, date)
}

func checkEnvVars() error {
	requiredVars := []string{"VAULT_ADDR", "S3BUCKET", "AWS_ENDPOINT_URL"}

	if os.Getenv("AWS_SHARED_CREDENTIALS_FILE") == "" {
		requiredVars = append(requiredVars, "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
	}

	if os.Getenv("AWS_REGION") == "" {
		os.Setenv("AWS_REGION", "auto")
		log.Printf("INFO: Defaulting AWS_REGION to auto")
	}

	var missingVars []string
	for _, envVar := range requiredVars {
		if os.Getenv(envVar) == "" {
			missingVars = append(missingVars, envVar)
		}
	}

	if len(missingVars) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missingVars, ", "))
	}

	return nil
}

func setupVaultClient() (*api.Client, error) {
	vaultAddr := os.Getenv("VAULT_ADDR")
	tokenFile := "/vault/secrets/token"

	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read Vault token: %w", err)
	}

	vaultClient, err := api.NewClient(&api.Config{Address: vaultAddr})
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	vaultClient.SetToken(strings.TrimSpace(string(token)))
	return vaultClient, nil
}

func createSnapshot(vaultClient *api.Client) (string, error) {
	snapshotPath := fmt.Sprintf("/tmp/vaultsnapshot-%s.snap", time.Now().Format("2006-01-02-15-04-05"))
	snapshotFile, err := os.Create(snapshotPath)
	if err != nil {
		return "", fmt.Errorf("failed to create snapshot file: %w", err)
	}
	defer snapshotFile.Close()

	if err := vaultClient.Sys().RaftSnapshot(snapshotFile); err != nil {
		return "", fmt.Errorf("failed to create Vault snapshot: %w", err)
	}

	log.Printf("INFO: Created local snapshot at %s", snapshotPath)
	return snapshotPath, nil
}

func newAWSSession() (*session.Session, error) {
	cfg := &aws.Config{
		Endpoint: aws.String(os.Getenv("AWS_ENDPOINT_URL")),
		Region:   aws.String(os.Getenv("AWS_REGION")),
	}

	if os.Getenv("AWS_SHARED_CREDENTIALS_FILE") == "" {
		cfg.Credentials = credentials.NewEnvCredentials()
	}

	return session.NewSession(cfg)
}

func uploadToS3(snapshotPath string, sess *session.Session) error {
	s3Client := s3.New(sess)
	s3Bucket := os.Getenv("S3BUCKET")

	file, err := os.Open(snapshotPath)
	if err != nil {
		return fmt.Errorf("failed to open snapshot file: %w", err)
	}
	defer file.Close()

	_, err = s3Client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String(filepath.Base(snapshotPath)),
		Body:   file,
	})
	if err != nil {
		return fmt.Errorf("failed to upload snapshot to S3: %w", err)
	}

	log.Printf("INFO: Successfully uploaded snapshot to s3://%s/%s", s3Bucket, filepath.Base(snapshotPath))
	return nil
}

func cleanupLocalAndRemote(snapshotPath string, sess *session.Session) {
	if err := os.Remove(snapshotPath); err != nil {
		log.Printf("WARNING: Failed to remove local snapshot: %v", err)
	} else {
		log.Printf("INFO: Removed local snapshot")
	}

	cleanupOldSnapshots(s3.New(sess), os.Getenv("S3BUCKET"))
}

func cleanupOldSnapshots(s3Client *s3.S3, bucket string) {
	retentionDays := 7
	if retentionStr := os.Getenv("VAULT_BACKUP_RETENTION"); retentionStr != "" {
		if retention, err := strconv.Atoi(retentionStr); err == nil && retention > 0 {
			retentionDays = retention
		} else {
			log.Printf("WARNING: Invalid VAULT_BACKUP_RETENTION, using default 7")
		}
	}

	s3List, err := s3Client.ListObjectsV2(&s3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	if err != nil {
		log.Printf("WARNING: Failed to list S3 objects: %v", err)
		return
	}

	var snapshots []struct {
		Key  string
		Time time.Time
	}

	for _, obj := range s3List.Contents {
		if strings.HasPrefix(*obj.Key, "vaultsnapshot-") {
			snapshots = append(snapshots, struct {
				Key  string
				Time time.Time
			}{Key: *obj.Key, Time: *obj.LastModified})
		}
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Time.After(snapshots[j].Time) // Sort by most recent first
	})

	if len(snapshots) <= retentionDays {
		return
	}

	for _, snap := range snapshots[retentionDays:] {
		_, err := s3Client.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(snap.Key),
		})
		if err != nil {
			log.Printf("WARNING: Failed to delete old snapshot %s: %v", snap.Key, err)
		} else {
			log.Printf("INFO: Deleted old snapshot: %s", snap.Key)
		}
	}
}
