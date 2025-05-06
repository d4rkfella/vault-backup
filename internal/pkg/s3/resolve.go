package s3

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithy "github.com/aws/smithy-go"
)

var ErrNoBackupFilesFound = errors.New("no backup files found in S3 bucket")
var ErrObjectNotFound = errors.New("S3 object not found")

func (c *Client) ResolveBackupKey(ctx context.Context) (string, error) {
	if c.config == nil {
		return "", fmt.Errorf("S3 client config is nil")
	}

	if filename := c.config.FileName; filename != "" {
		fmt.Printf("Specific backup filename provided: %s\n", filename)
		_, err := c.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(c.config.Bucket),
			Key:    aws.String(filename),
		})

		if err != nil {
			var nsk *types.NoSuchKey
			if errors.As(err, &nsk) {
				return "", fmt.Errorf("specified backup file '%s' not found in bucket '%s': %w", filename, c.config.Bucket, ErrObjectNotFound)
			}
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) {
				switch apiErr.ErrorCode() {
				case "NotFound", "NoSuchKey":
					return "", fmt.Errorf("%w: %q", ErrNoBackupFilesFound, filename)
				}
			}
			return "", fmt.Errorf("failed to check existence of specified backup file '%s': %w", filename, err)
		}
		return filename, nil
	}

	fmt.Println("No specific filename provided, finding latest backup...")
	var (
		latestKey  string
		latestTime time.Time
		foundAny   bool
		token      *string
	)

	fileNameRegex := regexp.MustCompile(`^raft_snapshot-(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\.snap$`)

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

			key := aws.ToString(obj.Key)
			matches := fileNameRegex.FindStringSubmatch(key)
			if len(matches) == 2 {
				ts, parseErr := time.Parse(time.RFC3339, matches[1])
				if parseErr == nil {
					if !foundAny || ts.After(latestTime) {
						latestTime = ts
						latestKey = key
						foundAny = true
					}
				}
			}
		}

		if out.NextContinuationToken == nil {
			break
		}
		token = out.NextContinuationToken
	}

	if !foundAny {
		return "", fmt.Errorf("no suitable backup snapshots found in bucket '%s'", c.config.Bucket)
	}

	fmt.Printf("Found latest backup: %s\n", latestKey)
	return latestKey, nil
}
