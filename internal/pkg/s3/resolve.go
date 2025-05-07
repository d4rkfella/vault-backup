package s3

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithy "github.com/aws/smithy-go"
)

func (c *Client) ResolveBackupKey(ctx context.Context) (string, error) {
	if filename := c.config.FileName; filename != "" {
		_, err := c.s3Client.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(c.config.Bucket),
			Key:    aws.String(filename),
		})

		if err != nil {
			var nsk *types.NoSuchKey
			if errors.As(err, &nsk) {
				return "", fmt.Errorf("the specified backup file '%q' was not found in bucket '%s'", filename, c.config.Bucket)
			}
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) {
				switch apiErr.ErrorCode() {
				case "NotFound", "NoSuchKey":
					return "", fmt.Errorf("the specified backup file '%q' was not found in bucket '%s'", filename, c.config.Bucket)
				}
			}
			return "", err
		}
		return filename, nil
	}

	fmt.Println("No backup filename was provided, searching for the latest available...")
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
			return "", err
		}

		for _, obj := range out.Contents {
			if obj.Key == nil || obj.LastModified == nil {
				continue
			}

			key := aws.ToString(obj.Key)

			if strings.HasSuffix(key, ".snap") {
				if !foundAny || obj.LastModified.After(latestTime) {
					latestTime = *obj.LastModified
					latestKey = key
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
		return "", fmt.Errorf("no suitable backup files were found in bucket '%s'", c.config.Bucket)
	}

	return latestKey, nil
}
