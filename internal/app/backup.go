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

func Backup(ctx context.Context, vaultClient VaultClient, s3Client S3Client, notifyClient NotifyClient) error {
	startTime := time.Now()
	var backupErr error
	var backupFilename string
	var snapshotSize int64

	defer func() {
		if notifyClient != nil {
			fmt.Println("Sending notification...")
			details := map[string]string{"File": backupFilename}
			if backupErr == nil && snapshotSize > 0 {
			} else {
				snapshotSize = 0
			}
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
	}()

	fmt.Println("Taking vault snapshot...")
	var buf bytes.Buffer
	if err := vaultClient.Backup(ctx, &buf); err != nil {
		backupErr = fmt.Errorf("vault snapshot failed: %w", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", backupErr)
		return backupErr
	}

	fmt.Println("Verifying snapshot checksums...")
	snapshotData := buf.Bytes()
	valid, err := verifyInternalChecksums(snapshotData)
	if err != nil {
		backupErr = fmt.Errorf("failed during snapshot verification: %w", err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", backupErr)
		return backupErr
	}
	if !valid {
		backupErr = fmt.Errorf("snapshot verification failed: checksum mismatch or invalid format")
		fmt.Fprintf(os.Stderr, "Error: %v\n", backupErr)
		return backupErr
	}
	fmt.Println("Snapshot verification successful.")

	snapshotSize = int64(len(snapshotData))

	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	backupFilename = fmt.Sprintf("raft_snapshot-%s.snap", timestamp)

	fmt.Printf("Uploading verified snapshot %s to S3...\n", backupFilename)
	if err := s3Client.PutObject(ctx, backupFilename, bytes.NewReader(snapshotData)); err != nil {
		backupErr = fmt.Errorf("failed to upload snapshot '%s' to S3: %w", backupFilename, err)
		fmt.Fprintf(os.Stderr, "Error: %v\n", backupErr)
		return backupErr
	}

	fmt.Println("Backup completed successfully")
	return nil
}
