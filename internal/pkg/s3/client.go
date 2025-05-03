package s3

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func NewClient(ctx context.Context) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(func() string {
			if region := os.Getenv("AWS_REGION"); region != "" {
				return region
			}
			return "auto"
		}()),
		config.WithCredentialsProvider(credentials.StaticCredentialsProvider{
			Value: aws.Credentials{
				AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
				SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
				SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
				Source:          "Environment variables",
			},
		}),
		config.WithClientOptions(func(o *s3.Options) {
			if algo := os.Getenv("AWS_S3_CHECKSUM_ALGORITHM"); algo != "" {
				o.UseChecksum = true
				o.ChecksumAlgorithm = s3.ChecksumAlgorithm(algo)
			}
		}),
	)

	if err != nil {
		return nil, err
	}

	svc := s3.NewFromConfig(cfg)

	return svc, nil
}
