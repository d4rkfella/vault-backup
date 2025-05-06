package s3

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	smithy "github.com/aws/smithy-go"
)

var ErrNoBackupFilesFound = errors.New("no backup files found in S3 bucket")

func (c *Client) ResolveBackupKey(ctx context.Context) (string, error) {
	if c.config == nil {
		return "", fmt.Errorf("S3 client config is nil")
	}

	if filename := c.config.FileName; filename != "" {
		_, err := c.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(c.config.Bucket),
			Key:    aws.String(filename),
		})

		if err != nil {
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) {
				switch apiErr.ErrorCode() {
				case "NotFound", "NoSuchKey":
					return "", fmt.Errorf("%w: %q", ErrNoBackupFilesFound, filename)
				}
			}
			return "", fmt.Errorf("failed to check S3 object: %w", err)
		}
		return filename, nil
	}

	var (
		latestKey  string
		latestTime time.Time
		foundAny   bool
		token      *string
	)

	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("search canceled: %w", ctx.Err())
		default:
		}

		out, err := c.s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            aws.String(c.config.Bucket),
			ContinuationToken: token,
		})
		if err != nil {
			return "", fmt.Errorf("failed to list S3 objects: %w", err)
		}

		for _, obj := range out.Contents {
			if obj.Key == nil || obj.LastModified == nil {
				continue
			}

			if filepath.Ext(*obj.Key) == ".snap" {
				if t := obj.LastModified.UTC(); !foundAny || t.After(latestTime) {
					latestKey = *obj.Key
					latestTime = t
					foundAny = true
				}
			}
		}

		if out.NextContinuationToken == nil {
			break
		}
		token = out.NextContinuationToken
	}

	if !foundAny {
		return "", ErrNoBackupFilesFound
	}
	return latestKey, nil
}
