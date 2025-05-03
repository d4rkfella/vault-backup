package s3

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type PutObjectInput struct {
	Bucket      string
	Key         string
	Body        io.Reader
	ContentType string
	Timeout     time.Duration
}

func (c *Client) PutObject(ctx context.Context, input PutObjectInput) error {
	timeout := input.Timeout
	if timeout == 0 {
		timeout = 1 * time.Minute
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	_, err := c.s3Client.PutObject(timeoutCtx, &s3.PutObjectInput{
		Bucket:      aws.String(input.Bucket),
		Key:         aws.String(input.Key),
		Body:        input.Body,
		ContentType: aws.String(input.ContentType),
	})
	if err != nil {
		return fmt.Errorf("failed to put object %s: %w", input.Key, err)
	}
	return nil
}
