package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/d4rkfella/vault-backup/internal/pkg/notify"
	"github.com/d4rkfella/vault-backup/internal/pkg/s3"
	"github.com/d4rkfella/vault-backup/internal/pkg/vault"
)

const (
	TIME_LAYOUT        = "20060102-150405"
	SNAPSHOT_EXTENSION = "snap"
)

type BackupConfig struct {
	VaultConfig  *vault.Config
	S3Config     *s3.Config
	NotifyConfig *notify.Config
}

func verifyInternalChecksums(data []byte) (bool, error) {
	reader := bytes.NewReader(data)

	gzReader, err := gzip.NewReader(reader)
	if err != nil {
		return false, fmt.Errorf("gzip error: %w", err)
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	expected := make(map[string]string)
	computed := make(map[string]string)

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("tar error: %w", err)
		}

		if hdr.Name == "SHA256SUMS" {
			content, err := io.ReadAll(tarReader)
			if err != nil {
				return false, fmt.Errorf("failed to read SHA256SUMS: %w", err)
			}
			expected = parseSHA256SUMS(content)
			break
		}
	}

	if len(expected) == 0 {
		return false, fmt.Errorf("SHA256SUMS file missing")
	}

	reader.Seek(0, 0)
	gzReader, _ = gzip.NewReader(reader)
	tarReader = tar.NewReader(gzReader)

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("tar error: %w", err)
		}

		if _, exists := expected[hdr.Name]; !exists {
			continue
		}

		h := sha256.New()
		if _, err := io.Copy(h, tarReader); err != nil {
			return false, fmt.Errorf("failed to hash %s: %w", hdr.Name, err)
		}
		computed[hdr.Name] = fmt.Sprintf("%x", h.Sum(nil))
	}

	for filename, expectedSum := range expected {
		actual, exists := computed[filename]
		if !exists {
			return false, fmt.Errorf("missing file %s in snapshot", filename)
		}
		if actual != expectedSum {
			return false, fmt.Errorf("checksum mismatch for %s (expected %s, got %s)",
				filename, expectedSum, actual)
		}
	}

	return true, nil
}

func parseSHA256SUMS(content []byte) map[string]string {
	sums := make(map[string]string)
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 2 {
			sums[parts[1]] = parts[0]
		}
	}
	return sums
}

func Backup(ctx context.Context, config BackupConfig) error {
	startTime := time.Now()
	fileName := fmt.Sprintf("backup-%s.%s", time.Now().Format(TIME_LAYOUT), SNAPSHOT_EXTENSION)
	var snapshotSize int64
	var err error

	var notifyClient *notify.Client
	if config.NotifyConfig != nil {
		notifyClient = notify.NewClient(*config.NotifyConfig)
	}

	defer func() {
		if notifyClient != nil {
			status := notify.NotificationStatus{
				Success:   err == nil,
				Duration:  time.Since(startTime),
				SizeBytes: snapshotSize,
				Error:     err,
				Type:      notify.NotificationTypeBackup,
				Additional: map[string]string{
					"File": fileName,
				},
			}
			if notifyErr := notifyClient.Notify(ctx, status); notifyErr != nil {
				fmt.Printf("Failed to send notification: %v\n", notifyErr)
			}
		}
	}()

	fmt.Println("Starting backup...")

	vaultClient, err := vault.NewClient(ctx, *config.VaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %w", err)
	}

	s3Client, err := s3.NewClient(ctx, *config.S3Config)
	if err != nil {
		return fmt.Errorf("failed to create s3 client: %w", err)
	}

	var buf bytes.Buffer

	if err := vaultClient.Backup(ctx, &buf); err != nil {
		return fmt.Errorf("failed to create vault backup: %w", err)
	}

	valid, err := verifyInternalChecksums(buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to verify backup: %w", err)
	}
	if !valid {
		return fmt.Errorf("backup verification failed")
	}

	snapshotSize = int64(buf.Len())
	reader := bytes.NewReader(buf.Bytes())

	if err := s3Client.PutObject(ctx, s3.PutObjectInput{
		Bucket:      config.S3Config.Bucket,
		Key:         fileName,
		Body:        reader,
		ContentType: "application/x-tar",
	}); err != nil {
		return fmt.Errorf("failed to upload backup to s3: %w", err)
	}

	fmt.Printf("Backup with name '%s' created and verified successfully\n", fileName)
	return nil
}
