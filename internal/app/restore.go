package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/d4rkfella/vault-backup/internal/pkg/notify"
	"github.com/d4rkfella/vault-backup/internal/pkg/s3"
	"github.com/d4rkfella/vault-backup/internal/pkg/vault"
)

func Restore(ctx context.Context, vaultCfg *vault.Config, s3Cfg *s3.Config, notifyCfg *notify.Config) error {
	startTime := time.Now()

	var notifyClient *notify.Client
	var restoreSize int64
	var restoreErr error
	var backupFile string

	vaultClient, err := vault.NewClient(ctx, vaultCfg)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %w", err)
	}

	s3Client, err := s3.NewClient(ctx, s3Cfg)
	if err != nil {
		return fmt.Errorf("failed to create s3 client: %w", err)
	}

	defer func() {
		if notifyCfg != nil {
			notifyClient = notify.NewClient(notifyCfg)

			status := notify.NotificationStatus{
				Success:   restoreErr == nil,
				Duration:  time.Since(startTime),
				SizeBytes: restoreSize,
				Error:     restoreErr,
				Type:      notify.NotificationTypeRestore,
			}
			if restoreErr == nil {
				status.Additional = map[string]string{
					"filename": backupFile,
				}
			}
			fmt.Println("Sending notification...")
			if err := notifyClient.Notify(ctx, status); err != nil {
				fmt.Printf("Warning: failed to send notification: %v\n", err)
			}
		}
		if vaultCfg.RevokeToken {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			fmt.Println("Revoking vault token...")
			if revokeErr := vaultClient.RevokeToken(cleanupCtx); revokeErr != nil {
				fmt.Printf("Warning: failed to revoke token: %v\n", revokeErr)
			}
		}
	}()

	backupFile = s3Cfg.FileName
	if backupFile == "" {
		fmt.Println("No specific backup file provided via config/flags, searching for the latest snapshot...")
		var findErr error
		backupFile, findErr = findLatestBackup(ctx, s3Client)
		if findErr != nil {
			restoreErr = fmt.Errorf("failed to find latest backup file: %w", findErr)
			fmt.Fprintf(os.Stderr, "Error: %v\n", restoreErr)
			return restoreErr
		}
		fmt.Printf("Found latest backup file: %s\n", backupFile)
	} else {
		fmt.Printf("Attempting to use user-specified backup file: %s\n", backupFile)
		fmt.Printf("Verifying specified backup file '%s' exists in S3...\n", backupFile)
		_, headErr := s3Client.HeadObject(ctx)
		if headErr != nil {
			restoreErr = fmt.Errorf("specified backup file %q not found or inaccessible: %w", backupFile, headErr)
			fmt.Fprintf(os.Stderr, "Error: %v\n", restoreErr)
			return restoreErr
		}
		fmt.Printf("Successfully verified specified backup file '%s' exists.\n", backupFile)
	}

	fmt.Printf("Proceeding with restore using backup file: %s\n", backupFile)

	reader, err := s3Client.GetObject(ctx, backupFile)
	if err != nil {
		restoreErr = fmt.Errorf("failed to download snapshot file: %w", err)
		return restoreErr
	}
	defer func() {
		if err := reader.Close(); err != nil {
			fmt.Printf("Warning: Failed to close reader: %v\n", err)
		}
	}()

	if err := vaultClient.Restore(ctx, reader); err != nil {
		restoreErr = fmt.Errorf("failed to restore snapshot: %w", err)
		return restoreErr
	}

	fmt.Println("Snapshot restore completed successfully")

	return nil
}

func findLatestBackup(ctx context.Context, s3Client *s3.Client) (string, error) {
	var latestKey string
	var latestTime time.Time
	var token *string

	for {
		out, err := s3Client.ListObjects(ctx, s3.ListObjectsInput{
			ContinuationToken: token,
		})
		if err != nil {
			return "", fmt.Errorf("listing page failed: %w", err)
		}

		for _, obj := range out.Contents {
			if obj.Key == nil || obj.LastModified == nil {
				continue
			}
			if filepath.Ext(*obj.Key) != ".snap" {
				continue
			}
			t := obj.LastModified.UTC()
			if latestKey == "" || t.After(latestTime) {
				latestKey = *obj.Key
				latestTime = t
			}
		}

		if out.NextContinuationToken == nil {
			break
		}
		token = out.NextContinuationToken
	}

	if latestKey == "" {
		return "", fmt.Errorf("no backup files were found")
	}
	return latestKey, nil
}
