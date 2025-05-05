package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	TIME_LAYOUT        = "20060102-150405"
	SNAPSHOT_EXTENSION = "snap"
)

func verifyInternalChecksums(data []byte) (bool, error) {
	reader := bytes.NewReader(data)
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return false, fmt.Errorf("gzip error: %w", err)
	}
	defer func() {
		if err := gzReader.Close(); err != nil {
			fmt.Printf("warning: failed to close gzip reader: %v\n", err)
		}
	}()

	tarReader := tar.NewReader(gzReader)
	var shaSumsContent []byte
	filesInTar := make(map[string][]byte)

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("tar read error: %w", err)
		}

		content, err := io.ReadAll(tarReader)
		if err != nil {
			return false, fmt.Errorf("failed to read file %s from tar: %w", hdr.Name, err)
		}

		if hdr.Name == "SHA256SUMS" {
			shaSumsContent = content
		}
		filesInTar[hdr.Name] = content
	}

	if shaSumsContent == nil {
		return false, fmt.Errorf("SHA256SUMS file not found in the archive")
	}

	expectedSums := parseSHA256SUMS(shaSumsContent)

	for name, expectedSum := range expectedSums {
		content, exists := filesInTar[name]
		if !exists {
			return false, fmt.Errorf("file %s listed in SHA256SUMS not found in archive", name)
		}

		h := sha256.New()
		if _, err := h.Write(content); err != nil {
			return false, fmt.Errorf("failed to hash content of %s: %w", name, err)
		}
		computedSum := fmt.Sprintf("%x", h.Sum(nil))

		if computedSum != expectedSum {
			return false, fmt.Errorf("checksum mismatch for %s (expected %s, got %s)",
				name, expectedSum, computedSum)
		}
	}
	return true, nil
}

func parseSHA256SUMS(content []byte) map[string]string {
	sums := make(map[string]string)
	lines := bytes.Split(content, []byte("\n"))
	for _, line := range lines {
		trimmedLine := bytes.TrimSpace(line)
		if len(trimmedLine) == 0 {
			continue
		}
		parts := bytes.Fields(trimmedLine)
		if len(parts) == 2 {
			sums[string(parts[1])] = string(parts[0])
		}
	}
	return sums
}

func Backup(ctx context.Context, vaultClient VaultClient, s3Client S3Client, notifyClient NotifyClient, revokeToken bool) error {
	startTime := time.Now()
	fileName := fmt.Sprintf("backup-%s.%s", startTime.Format(TIME_LAYOUT), SNAPSHOT_EXTENSION)
	var snapshotSize int64
	var backupErr error

	defer func() {
		if notifyClient != nil {
			fmt.Println("Sending notification...")
			details := map[string]string{"File": fileName}
			if notifyErr := notifyClient.Notify(
				ctx,
				backupErr == nil,
				"backup",
				time.Since(startTime),
				snapshotSize,
				backupErr,
				details,
			); notifyErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to send notification: %v\n", notifyErr)
			}
		}

		if revokeToken {
			fmt.Printf("DEBUG: In app/backup.go defer, attempting token revocation (revokeToken=%t)\n", revokeToken)
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			if revokeErr := vaultClient.RevokeToken(cleanupCtx); revokeErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to revoke vault token: %v\n", revokeErr)
			}
		} else {
			fmt.Printf("DEBUG: In app/backup.go defer, skipping token revocation (revokeToken=%t)\n", revokeToken)
		}
	}()

	fmt.Println("Starting backup...")

	var buf bytes.Buffer
	if err := vaultClient.Backup(ctx, &buf); err != nil {
		backupErr = fmt.Errorf("failed to create vault backup: %w", err)
		return backupErr
	}

	fmt.Println("Verifying snapshot checksums...")
	valid, err := verifyInternalChecksums(buf.Bytes())
	if err != nil {
		backupErr = fmt.Errorf("failed during snapshot verification: %w", err)
		return backupErr
	}
	if !valid {
		backupErr = fmt.Errorf("snapshot verification failed: checksum mismatch or missing files")
		return backupErr
	}
	fmt.Println("Snapshot verification successful.")

	snapshotSize = int64(buf.Len())
	reader := bytes.NewReader(buf.Bytes())

	fmt.Printf("Uploading verified snapshot '%s' (%d bytes) to S3...\n", fileName, snapshotSize)
	if err := s3Client.PutObject(ctx, fileName, reader); err != nil {
		backupErr = fmt.Errorf("failed to upload backup to s3: %w", err)
		return backupErr
	}

	fmt.Printf("Backup '%s' created, verified, and uploaded successfully.\n", fileName)
	return nil
}
