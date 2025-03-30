package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
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
	setupSystemResources()
	
	checkEnvVars()

	vaultClient := setupVaultClient()

	snapshotPath := createSnapshot(vaultClient)

	uploadToS3(snapshotPath)

	cleanupLocalAndRemote(snapshotPath)
}

func setupSystemResources() {
    undo, err := maxprocs.Set(maxprocs.Logger(log.Printf))
    defer undo()
    if err != nil {
        log.Printf("WARNING: failed to set GOMAXPROCS: %v", err)
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
        log.Printf("WARNING: failed to set GOMEMLIMIT: %v", err)
    } else {
        log.Printf("DEBUG: GOMEMLIMIT: %d bytes", memLimit)
    }

    log.Printf("INFO: Starting vault-backup")
    log.Printf("INFO: Version: %s", version)
    log.Printf("INFO: Commit: %s", commit)
    log.Printf("INFO: Build date: %s", date)
}

func setupVaultClient() *api.Client {
	vaultAddr := os.Getenv("VAULT_ADDR")
	tokenFile := "/vault/secrets/token"

	token, err := os.ReadFile(tokenFile)
	if err != nil {
		log.Fatalf("ERROR: Failed to read Vault token from %s: %v", tokenFile, err)
	}

	vaultClient, err := api.NewClient(&api.Config{Address: vaultAddr})
	if err != nil {
		log.Fatalf("ERROR: Failed to create Vault client: %v", err)
	}

	vaultClient.SetToken(strings.TrimSpace(string(token)))
	return vaultClient
}

func createSnapshot(vaultClient *api.Client) string {
	snapshotPath := fmt.Sprintf("/tmp/vaultsnapshot-%s.snap", time.Now().Format("2006-01-02-15-04-05"))
	snapshotFile, err := os.Create(snapshotPath)
	if err != nil {
		log.Fatalf("ERROR: Failed to create snapshot file: %v", err)
	}
	defer snapshotFile.Close()

	if err := vaultClient.Sys().RaftSnapshot(snapshotFile); err != nil {
		log.Fatalf("ERROR: Failed to create Vault snapshot: %v", err)
	}

	log.Printf("INFO: Created local snapshot at %s", snapshotPath)
	return snapshotPath
}

func uploadToS3(snapshotPath string) {
	cfg := &aws.Config{
		Endpoint: aws.String(os.Getenv("AWS_ENDPOINT_URL")),
		Region:   aws.String(os.Getenv("AWS_REGION")),
	}

	if os.Getenv("AWS_SHARED_CREDENTIALS_FILE") == "" {
		cfg.Credentials = credentials.NewEnvCredentials()
	} else {
		os.Setenv("AWS_SDK_LOAD_CONFIG", "1")
	}

	sess, err := session.NewSession(cfg)
	if err != nil {
		log.Fatalf("ERROR: Failed to create AWS session: %v", err)
	}

	s3Client := s3.New(sess)
	s3Bucket := os.Getenv("S3BUCKET")

	file, err := os.Open(snapshotPath)
	if err != nil {
		log.Fatalf("ERROR: Failed to open snapshot file: %v", err)
	}
	defer file.Close()

	_, err = s3Client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String(filepath.Base(snapshotPath)),
		Body:   file,
	})
	if err != nil {
		log.Fatalf("ERROR: Failed to upload snapshot to S3: %v", err)
	}

	log.Printf("INFO: Successfully uploaded snapshot to s3://%s/%s", s3Bucket, filepath.Base(snapshotPath))
}

func cleanupLocalAndRemote(snapshotPath string) {
	if err := os.Remove(snapshotPath); err != nil {
		log.Printf("WARNING: Failed to remove local snapshot file: %v", err)
	} else {
		log.Printf("INFO: Removed local snapshot file")
	}

	s3Bucket := os.Getenv("S3BUCKET")
	cfg := &aws.Config{
		Endpoint: aws.String(os.Getenv("AWS_ENDPOINT_URL")),
		Region:   aws.String(os.Getenv("AWS_REGION")),
	}

	if os.Getenv("AWS_SHARED_CREDENTIALS_FILE") == "" {
		cfg.Credentials = credentials.NewEnvCredentials()
	}

	sess, err := session.NewSession(cfg)
	if err != nil {
		log.Printf("WARNING: Failed to create AWS session for cleanup: %v", err)
		return
	}

	cleanupOldSnapshots(s3.New(sess), s3Bucket)
}

func checkEnvVars() {
	requiredVars := []string{
		"VAULT_ADDR",
		"S3BUCKET",
		"AWS_ENDPOINT_URL",
	}

	if os.Getenv("AWS_SHARED_CREDENTIALS_FILE") == "" {
		requiredVars = append(requiredVars, "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
	}

	if os.Getenv("AWS_REGION") == "" {
		os.Setenv("AWS_REGION", "auto")
		log.Printf("INFO: Defaulting AWS_REGION=auto for Cloudflare R2")
	}

	for _, envVar := range requiredVars {
		if os.Getenv(envVar) == "" {
			log.Fatalf("ERROR: Missing required environment variable: %s", envVar)
		}
	}
}

func cleanupOldSnapshots(s3Client *s3.S3, bucket string) {
	snapshotRetention := 7

	s3List, err := s3Client.ListObjectsV2(&s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		log.Printf("WARNING: Failed to list S3 objects: %v", err)
		return
	}

	var snapshots []string
	for _, obj := range s3List.Contents {
		if strings.HasPrefix(*obj.Key, "vaultsnapshot-") {
			snapshots = append(snapshots, *obj.Key)
		}
	}

	if len(snapshots) <= snapshotRetention {
		return
	}

	sort.Sort(sort.Reverse(sort.StringSlice(snapshots)))
	for _, snapshot := range snapshots[snapshotRetention:] {
		_, err := s3Client.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(snapshot),
		})
		if err != nil {
			log.Printf("WARNING: Failed to delete old snapshot %s: %v", snapshot, err)
		} else {
			log.Printf("INFO: Deleted old snapshot: %s", snapshot)
		}
	}
}
