package app

import (
	"bytes"
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

	fmt.Println("Resolving backup key...")
	resolvedKey, err := s3Client.ResolveBackupKey(ctx)
	if err != nil {
		restoreErr = fmt.Errorf("failed to resolve backup key: %w", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", restoreErr)
		return restoreErr
	}
	backupFilename = resolvedKey
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
