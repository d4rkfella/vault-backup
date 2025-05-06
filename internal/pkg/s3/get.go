package s3

import (
	"context"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func (c *Client) GetObject(ctx context.Context, key string) (body io.ReadCloser, sizeBytes int64, err error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(c.config.Bucket),
		Key:    aws.String(key),
	}

	result, err := c.s3Client.GetObject(ctx, input)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get S3 object '%s': %w", key, err)
	}

	var size int64
	if result.ContentLength != nil {
		size = *result.ContentLength
	}

	return result.Body, size, nil
}
