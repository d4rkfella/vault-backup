package app

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"time"

	"github.com/darkfella/vault-backup/internal/pkg/notify"
	"github.com/darkfella/vault-backup/internal/pkg/s3"
	"github.com/darkfella/vault-backup/internal/pkg/vault"
)

type RestoreConfig struct {
	VaultConfig  *vault.Config
	S3Config     *s3.Config
	NotifyConfig *notify.Config
	BackupFile   string
	ForceRestore bool
}

func Restore(ctx context.Context, config *RestoreConfig) error {
	vaultClient, err := vault.NewClient(config.VaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %w", err)
	}
	defer vaultClient.Close()

	s3Client, err := s3.NewClient(config.S3Config)
	if err != nil {
		return fmt.Errorf("failed to create s3 client: %w", err)
	}

	var notifyClient *notify.Client
	if config.NotifyConfig != nil {
		notifyClient, err = notify.NewClient(config.NotifyConfig)
		if err != nil {
			return fmt.Errorf("failed to create notification client: %w", err)
		}
	}

	startTime := time.Now()
	var restoreSize int64
	var restoreErr error

	defer func() {
		if notifyClient != nil {
			status := notify.NotificationStatus{
				Success:  restoreErr == nil,
				Duration: time.Since(startTime),
				Size:     restoreSize,
				Error:    restoreErr,
				Type:     notify.Restore,
			}
			if restoreErr == nil {
				status.Metadata = map[string]string{
					"filename": config.BackupFile,
				}
			}
			notifyClient.Notify(ctx, status)
		}
	}()

	if config.BackupFile == "" {
		config.BackupFile, err = findLatestBackup(ctx, s3Client)
		if err != nil {
			restoreErr = fmt.Errorf("failed to find latest backup: %w", err)
			return restoreErr
		}
	}

	reader, err := s3Client.GetObject(ctx, config.BackupFile)
	if err != nil {
		restoreErr = fmt.Errorf("failed to get backup file: %w", err)
		return restoreErr
	}
	defer reader.Close()

	if err := vaultClient.Restore(ctx, reader, config.ForceRestore); err != nil {
		restoreErr = fmt.Errorf("failed to restore vault: %w", err)
		return restoreErr
	}

	return nil
}

func findLatestBackup(ctx context.Context, s3Client *s3.Client) (string, error) {
	objects, err := s3Client.ListObjects(ctx, "")
	if err != nil {
		return "", fmt.Errorf("failed to list objects: %w", err)
	}

	var backups []struct {
		key  string
		date time.Time
	}

	for _, obj := range objects {
		if filepath.Ext(obj.Key) == ".snap" {
			backups = append(backups, struct {
				key  string
				date time.Time
			}{
				key:  obj.Key,
				date: obj.LastModified,
			})
		}
	}

	if len(backups) == 0 {
		return "", fmt.Errorf("no backup files found")
	}

	// Sort by date (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].date.After(backups[j].date)
	})

	return backups[0].key, nil
}
