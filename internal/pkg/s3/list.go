package s3

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type ListObjectsInput struct {
	Bucket    string
	Prefix    string
	Delimiter string
	MaxKeys   int32
}

type ListObjectsOutput struct {
	Contents       []s3.Object
	CommonPrefixes []string
	IsTruncated    bool
	NextMarker     *string
}

func ListObjects(ctx context.Context, client *s3.Client, input ListObjectsInput) (*ListObjectsOutput, error) {
	var allContents []s3.Object
	var allCommonPrefixes []string
	var isTruncated bool
	var nextMarker *string

	timeoutCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	err := client.ListObjectsV2PagesWithContext(timeoutCtx, &s3.ListObjectsV2Input{
		Bucket:    &input.Bucket,
		Prefix:    &input.Prefix,
		Delimiter: &input.Delimiter,
		MaxKeys:   &input.MaxKeys,
	}, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		allContents = append(allContents, page.Contents...)
		allCommonPrefixes = append(allCommonPrefixes, page.CommonPrefixes...)
		isTruncated = page.IsTruncated
		nextMarker = page.NextContinuationToken
		return !lastPage
	})

	if err != nil {
		return nil, err
	}

	return &ListObjectsOutput{
		Contents:       allContents,
		CommonPrefixes: allCommonPrefixes,
		IsTruncated:    isTruncated,
		NextMarker:     nextMarker,
	}, nil
}
