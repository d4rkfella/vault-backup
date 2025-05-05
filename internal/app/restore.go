package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"
)

func Restore(ctx context.Context, vaultClient VaultClient, s3Client S3Client, notifyClient NotifyClient, filename string) error {
	startTime := time.Now()
	var restoreErr error
	var backupFilename string
	var snapshotSize int64

	defer func() {
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

	if filename == "" {
		fmt.Println("No specific backup file provided, searching for the latest snapshot...")
		latestBackup, err := s3Client.FindLatestSnapshotKey(ctx)
		if err != nil {
			restoreErr = fmt.Errorf("failed to find latest backup: %w", err)
			return restoreErr
		}
		filename = latestBackup
		fmt.Printf("Found latest backup file: %s\n", filename)
	} else {
		fmt.Printf("Attempting restore with specified file: %s\n", filename)
		if exists, err := s3Client.HeadObject(ctx, filename); err != nil {
			restoreErr = fmt.Errorf("failed to check for backup file %q: %w", filename, err)
			fmt.Fprintf(os.Stderr, "Error: %v\n", restoreErr)
			return restoreErr
		} else if !exists {
			restoreErr = fmt.Errorf("specified backup file %q not found", filename)
			fmt.Fprintf(os.Stderr, "Error: %v\n", restoreErr)
			return restoreErr
		}
	}
	backupFilename = filename

	fmt.Printf("Proceeding with restore using backup file: %s\n", backupFilename)

	objReader, err := s3Client.GetObject(ctx, backupFilename)
	if err != nil {
		restoreErr = fmt.Errorf("failed to download backup '%s': %w", backupFilename, err)
		return restoreErr
	}
	defer func() {
		if err := objReader.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close S3 object reader: %v\n", err)
		}
	}()

	var buf bytes.Buffer
	snapshotSize, err = io.Copy(&buf, objReader)
	if err != nil {
		restoreErr = fmt.Errorf("failed to read downloaded backup data for '%s': %w", backupFilename, err)
		return restoreErr
	}

	if err := vaultClient.Restore(ctx, &buf); err != nil {
		restoreErr = fmt.Errorf("failed to restore vault backup '%s': %w", backupFilename, err)
		return restoreErr
	}

	fmt.Println("Snapshot restore completed successfully")
	return nil
}
