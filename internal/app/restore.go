package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"
)

func Restore(ctx context.Context, vaultClient VaultClient, s3Client S3Client, notifyClient NotifyClient) error {
	startTime := time.Now()
	var restoreErr error
	var backupFilename string
	var snapshotSize int64
	var objReader io.ReadCloser

	defer func() {
		if objReader != nil {
			if err := objReader.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to close S3 object reader: %v\n", err)
			}
		}
		if notifyClient != nil {
			fmt.Println("Sending notification...")
			details := map[string]string{"File": backupFilename}
			if notifyErr := notifyClient.Notify(
				ctx,
				restoreErr == nil,
				"restore",
				time.Since(startTime),
				snapshotSize,
				restoreErr,
				details,
			); notifyErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to send notification: %v\n", notifyErr)
			}
		}
	}()

	resolvedKey, err := s3Client.ResolveBackupKey(ctx)
	if err != nil {
		restoreErr = fmt.Errorf("failed resolving the backup file to use: %w", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", restoreErr)
		return restoreErr
	}
	backupFilename = resolvedKey

	fmt.Printf("Getting backup file %s from S3...", backupFilename)
	objReader, snapshotSize, err = s3Client.GetObject(ctx, backupFilename)
	if err != nil {
		restoreErr = fmt.Errorf("failed to get backup object '%s': %w", backupFilename, err)
		return restoreErr
	}

	fmt.Printf("Backup size: %d bytes\n", snapshotSize)

	fmt.Println("Restoring Vault snapshot...")
	if err := vaultClient.Restore(ctx, objReader); err != nil {
		restoreErr = fmt.Errorf("failed to restore vault backup '%s': %w", backupFilename, err)
		return restoreErr
	}

	fmt.Println("Snapshot restore completed successfully")
	restoreErr = nil
	return nil
}
