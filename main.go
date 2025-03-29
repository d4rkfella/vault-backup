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
	undo, err := maxprocs.Set(maxprocs.Logger(log.Printf))
	defer undo()
	if err != nil {
		log.Printf("WARNING: failed to set GOMAXPROCS: %v", err)
	}

	memLimit, err := memlimit.SetGoMemLimitWithOpts(memlimit.WithProvider(memlimit.ApplyFallback(memlimit.FromCgroupHybrid, memlimit.FromSystem)))
	if err != nil {
		log.Printf("WARNING: failed to set GOMEMLIMIT: %v", err)
	}

	checkEnvVars()

	vaultAddr := os.Getenv("VAULT_ADDR")
	tokenFile := "/vault/secrets/token"

	token, err := os.ReadFile(tokenFile)
	if err != nil {
		log.Fatalf("Failed to read Vault token: %v", err)
	}

	vaultClient, err := api.NewClient(&api.Config{Address: vaultAddr})
	if err != nil {
		log.Fatalf("Failed to create Vault client: %v", err)
	}
	vaultClient.SetToken(strings.TrimSpace(string(token)))

	log.Printf("INFO: Starting vault-backup")
	log.Printf("INFO: Version: %s", version)
	log.Printf("INFO: Commit: %s", commit)
	log.Printf("INFO: Build date: %s", date)
	
	log.Printf("DEBUG: GOMEMLIMIT: %d bytes", memLimit)
	
	snapshotPath := fmt.Sprintf("/tmp/vaultsnapshot-%s.snap", time.Now().Format("2006-01-02-15-04-05"))
	snapshotFile, err := os.Create(snapshotPath)
	if err != nil {
		log.Fatalf("Failed to create snapshot file: %v", err)
	}
	defer snapshotFile.Close()

	if err := vaultClient.Sys().RaftSnapshot(snapshotFile); err != nil {
		log.Fatalf("Failed to create Vault snapshot: %v", err)
	}

	s3Bucket := os.Getenv("S3BUCKET")

	sess, err := session.NewSession()
	if err != nil {
		log.Fatalf("Failed to create AWS session: %v", err)
	}

	s3Client := s3.New(sess)

	file, err := os.Open(snapshotPath)
	if err != nil {
		log.Fatalf("Failed to open snapshot file: %v", err)
	}
	defer file.Close()

	_, err = s3Client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String(filepath.Base(snapshotPath)),
		Body:   file,
	})
	if err != nil {
		log.Fatalf("Failed to upload snapshot to S3: %v", err)
	}

	log.Println("Backup completed successfully")
	os.Remove(snapshotPath)

	cleanupOldSnapshots(s3Client, s3Bucket)
}

func checkEnvVars() {
	requiredVars := []string{
		"VAULT_ADDR",
		"S3BUCKET",
		"AWS_ENDPOINT_URL",
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
	}

	for _, envVar := range requiredVars {
		if os.Getenv(envVar) == "" {
			log.Fatalf("Missing required environment variable: %s", envVar)
		}
	}

	if os.Getenv("AWS_SHARED_CREDENTIALS_FILE") == "" {
		if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
			log.Fatalf("Missing AWS credentials: Either set AWS_SHARED_CREDENTIALS_FILE or AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY")
		}
	}
}

func cleanupOldSnapshots(s3Client *s3.S3, bucket string) {
	snapshotRetention := 7

	s3List, err := s3Client.ListObjectsV2(&s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		log.Fatalf("Failed to list S3 objects: %v", err)
	}

	var snapshots []string
	for _, obj := range s3List.Contents {
		if strings.HasPrefix(*obj.Key, "vaultsnapshot-") {
			snapshots = append(snapshots, *obj.Key)
		}
	}

	sort.Sort(sort.Reverse(sort.StringSlice(snapshots)))
	if len(snapshots) <= snapshotRetention {
		return
	}

	for _, snapshot := range snapshots[snapshotRetention:] {
		_, err := s3Client.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(snapshot),
		})
		if err != nil {
			log.Printf("Failed to delete old snapshot %s: %v", snapshot, err)
		} else {
			log.Printf("Deleted old snapshot: %s", snapshot)
		}
	}
}
