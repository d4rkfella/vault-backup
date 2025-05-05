package s3

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type ListObjectsInput struct {
	Prefix            string
	Delimiter         string
	ContinuationToken *string
}

type ListObjectsOutput struct {
	Contents              []types.Object
	CommonPrefixes        []types.CommonPrefix
	IsTruncated           *bool
	NextContinuationToken *string
}

func (c *Client) ListObjects(ctx context.Context, input ListObjectsInput) (*ListObjectsOutput, error) {

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	paginator := s3.NewListObjectsV2Paginator(c.s3Client, &s3.ListObjectsV2Input{
		Bucket:            aws.String(c.config.Bucket),
		Prefix:            aws.String(input.Prefix),
		Delimiter:         aws.String(input.Delimiter),
		MaxKeys:           aws.Int32(1000),
		ContinuationToken: input.ContinuationToken,
	})

	var result ListObjectsOutput
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(timeoutCtx)
		if err != nil {
			return nil, fmt.Errorf("list objects pagination failed: %w", err)
		}

		result.Contents = append(result.Contents, page.Contents...)
		result.CommonPrefixes = append(result.CommonPrefixes, page.CommonPrefixes...)
		result.IsTruncated = page.IsTruncated
		result.NextContinuationToken = page.NextContinuationToken
	}

	return &result, nil
}
