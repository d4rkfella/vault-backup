package s3

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"time"
)

func (c *Client) HeadObject(ctx context.Context) (*s3.HeadObjectOutput, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	output, err := c.s3Client.HeadObject(timeoutCtx, &s3.HeadObjectInput{
		Bucket: aws.String(c.config.Bucket),
		Key:    aws.String(c.config.FileName),
	})

	if err != nil {
		return nil, fmt.Errorf("head object failed for %s: %w", c.config.FileName, err)
	}
	return output, nil
}
