package s3

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var ErrNoBackupFilesFound = errors.New("no backup files found in S3 bucket")

func (c *Client) FindLatestSnapshotKey(ctx context.Context) (string, error) {
	var latestKey string
	var latestTime time.Time
	var token *string

	for {
		sdkInput := &s3.ListObjectsV2Input{
			Bucket:            aws.String(c.config.Bucket),
			ContinuationToken: token,
		}

		out, err := c.s3Client.ListObjectsV2(ctx, sdkInput)
		if err != nil {
			return "", fmt.Errorf("listing page failed: %w", err)
		}

		for _, obj := range out.Contents {
			if obj.Key == nil || obj.LastModified == nil {
				continue
			}
			key := *obj.Key
			if filepath.Ext(key) != ".snap" {
				continue
			}
			t := obj.LastModified.UTC()
			if latestKey == "" || t.After(latestTime) {
				latestKey = key
				latestTime = t
			}
		}

		if out.NextContinuationToken == nil {
			break
		}
		token = out.NextContinuationToken
	}

	if latestKey == "" {
		return "", ErrNoBackupFilesFound
	}
	return latestKey, nil
}
