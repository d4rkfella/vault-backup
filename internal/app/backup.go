package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"time"
)

const (
	TIME_LAYOUT        = "20060102-150405"
	SNAPSHOT_EXTENSION = "snap"
)

func verifyInternalChecksums(data []byte) error {
	reader := bytes.NewReader(data)
	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return fmt.Errorf("gzip error: %w", err)
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
			return fmt.Errorf("tar error: %w", err)
		}

		content, err := io.ReadAll(tarReader)
		if err != nil {
			return fmt.Errorf("failed to read file %s from tar: %w", hdr.Name, err)
		}

		if hdr.Name == "SHA256SUMS" {
			shaSumsContent = content
		}
		filesInTar[hdr.Name] = content
	}

	if shaSumsContent == nil {
		return fmt.Errorf("SHA256SUMS file not found in the archive")
	}

	expectedSums := parseSHA256SUMS(shaSumsContent)

	for name, expectedSum := range expectedSums {
		content, exists := filesInTar[name]
		if !exists {
			return fmt.Errorf("file %s listed in SHA256SUMS not found in archive", name)
		}

		h := sha256.New()
		if _, err := h.Write(content); err != nil {
			return fmt.Errorf("failed to calculate hash for %s: %w", name, err)
		}
		computedSum := fmt.Sprintf("%x", h.Sum(nil))

		if computedSum != expectedSum {
			return fmt.Errorf("checksum mismatch for %s (expected %s, got %s)",
				name, expectedSum, computedSum)
		}
	}
	return nil
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

func Backup(ctx context.Context, vaultClient VaultClient, s3Client S3Client) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	
	var err error
	fileName := fmt.Sprintf("backup-%s.%s", time.Now().Format(TIME_LAYOUT), SNAPSHOT_EXTENSION)

	fmt.Println("Starting backup...")

	var buf bytes.Buffer
	if err = vaultClient.Backup(timeoutCtx, &buf); err != nil {
		return fmt.Errorf("creating raft snapshot failed: %w", err)
	}

	snapshotData := buf.Bytes()
	if err = verifyInternalChecksums(snapshotData); err != nil {
		return fmt.Errorf("snapshot verification failed: %w", err)
	}

	if err = s3Client.PutObject(timeoutCtx, fileName, bytes.NewReader(snapshotData)); err != nil {
		return fmt.Errorf("s3 upload operation failed: %w", err)
	}

	fmt.Printf("Backup with name '%s' created.\n", fileName)
	return nil
}
