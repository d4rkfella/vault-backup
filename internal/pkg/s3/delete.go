package s3

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type DeleteObjectsInput struct {
	Bucket string
	Keys   []string
}

type DeleteObjectsOutput struct {
	Deleted []s3.DeletedObject
	Errors  []s3.Error
}

func DeleteObjects(ctx context.Context, client *s3.Client, input DeleteObjectsInput) (*DeleteObjectsOutput, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	objects := make([]s3.ObjectIdentifier, len(input.Keys))
	for i, key := range input.Keys {
		objects[i] = s3.ObjectIdentifier{Key: &key}
	}

	quiet := false
	output, err := client.DeleteObjectsWithContext(timeoutCtx, &s3.DeleteObjectsInput{
		Bucket: &input.Bucket,
		Delete: &s3.Delete{
			Objects: objects,
			Quiet:   &quiet,
		},
	})

	if err != nil {
		return nil, err
	}

	return &DeleteObjectsOutput{
		Deleted: output.Deleted,
		Errors:  output.Errors,
	}, nil
}
