package s3

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Config struct {
	AccessKey       string
	SecretAccessKey string
	SessionToken    string
	Region          string
	Bucket          string
	Endpoint        string
	FileName        string
}

type Client struct {
	s3Client s3API
	config   *Config
}

func NewClient(ctx context.Context, cfg *Config) (*Client, error) {

	creds := credentials.NewStaticCredentialsProvider(
		cfg.AccessKey,
		cfg.SecretAccessKey,
		cfg.SessionToken,
	)

	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.Region),
		config.WithCredentialsProvider(creds),
	)
	if err != nil {
		return nil, err
	}

	opts := []func(*s3.Options){}
	if cfg.Endpoint != "" {
		opts = append(opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = true
		})
	}

	return &Client{
		s3Client: s3.NewFromConfig(awsCfg, opts...),
		config:   cfg,
	}, nil
}
