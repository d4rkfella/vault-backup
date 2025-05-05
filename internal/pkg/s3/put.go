package s3

import (
	"context"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func (c *Client) PutObject(ctx context.Context, key string, body io.Reader) error {

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	_, err := c.s3Client.PutObject(timeoutCtx, &s3.PutObjectInput{
		Bucket:      aws.String(c.config.Bucket),
		Key:         aws.String(key),
		Body:        body,
		ContentType: aws.String("application/gzip"),
	})
	if err != nil {
		return err
	}
	return nil
}
