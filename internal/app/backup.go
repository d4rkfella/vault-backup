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

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, fmt.Errorf("tar error: %w", err)
		}

		content, err := io.ReadAll(tarReader)
		if err != nil {
			return false, fmt.Errorf("failed to read file %s: %w", hdr.Name, err)
		}

		if hdr.Name == "SHA256SUMS" {
			shaSumsContent = content
		} else {
			expected := parseSHA256SUMS(shaSumsContent)
			if expectedSum, exists := expected[hdr.Name]; exists {
				h := sha256.New()
				if _, err := h.Write(content); err != nil {
					return false, fmt.Errorf("failed to hash %s: %w", hdr.Name, err)
				}
				computedSum := fmt.Sprintf("%x", h.Sum(nil))
				if computedSum != expectedSum {
					return false, fmt.Errorf("checksum mismatch for %s (expected %s, got %s)",
						hdr.Name, expectedSum, computedSum)
				}
			}
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

func Backup(ctx context.Context, vaultCfg *vault.Config, s3Cfg *s3.Config, notifyCfg *notify.Config) error {
	startTime := time.Now()
	fileName := fmt.Sprintf("backup-%s.%s", time.Now().Format(TIME_LAYOUT), SNAPSHOT_EXTENSION)

	var notifyClient *notify.Client
	var snapshotSize int64
	var err error

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
				Success:   err == nil,
				Duration:  time.Since(startTime),
				SizeBytes: snapshotSize,
				Error:     err,
				Type:      notify.NotificationTypeBackup,
				Additional: map[string]string{
					"File": fileName,
				},
			}
			fmt.Println("Sending notification...")
			if notifyErr := notifyClient.Notify(ctx, status); notifyErr != nil {
				fmt.Printf("Failed to send notification: %v\n", notifyErr)
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

	var buf bytes.Buffer
	fmt.Println("Creating backup...")
	if err := vaultClient.Backup(ctx, &buf); err != nil {
		return fmt.Errorf("failed to create vault backup: %w", err)
	}

	fmt.Println("Verifying checksums...")
	valid, err := verifyInternalChecksums(buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to verify backup: %w", err)
	}
	if !valid {
		return fmt.Errorf("backup verification failed")
	}

	snapshotSize = int64(buf.Len())
	reader := bytes.NewReader(buf.Bytes())

	fmt.Println("Uploading to s3 bucket...")
	if err := s3Client.PutObject(ctx, fileName, reader); err != nil {
		return fmt.Errorf("failed to upload backup to s3: %w", err)
	}

	fmt.Printf("Backup process completed sucesfully")
	return nil
}
