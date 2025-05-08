package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestNewClient(t *testing.T) {
	ctx := context.Background()

	t.Run("successful client creation with minimal config", func(t *testing.T) {
		cfg := &Config{
			Region:          "us-east-1",
			AccessKey:       "testKey",
			SecretAccessKey: "testSecret",
		}
		client, err := NewClient(ctx, cfg)
		if err != nil {
			t.Fatalf("NewClient() error = %v, want nil", err)
		}
		if client == nil {
			t.Fatal("NewClient() client = nil, want non-nil client")
		}
		if client.config.Region != cfg.Region {
			t.Errorf("client.config.Region = %s, want %s", client.config.Region, cfg.Region)
		}
	})

	t.Run("successful client creation with endpoint", func(t *testing.T) {
		cfg := &Config{
			Region:          "us-west-2",
			AccessKey:       "testKey",
			SecretAccessKey: "testSecret",
			Endpoint:        "http://localhost:9000",
		}
		client, err := NewClient(ctx, cfg)
		if err != nil {
			t.Fatalf("NewClient() error = %v, want nil", err)
		}
		if client == nil {
			t.Fatal("NewClient() client = nil, want non-nil client")
		}
		if client.config.Endpoint != cfg.Endpoint {
			t.Errorf("client.config.Endpoint = %s, want %s", client.config.Endpoint, cfg.Endpoint)
		}
	})

}

type mockS3APIClient struct {
	GetObjectFunc     func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	PutObjectFunc     func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	ListObjectsV2Func func(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
	HeadObjectFunc    func(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

func (m *mockS3APIClient) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if m.GetObjectFunc != nil {
		return m.GetObjectFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *mockS3APIClient) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if m.PutObjectFunc != nil {
		return m.PutObjectFunc(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *mockS3APIClient) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	if m.ListObjectsV2Func != nil {
		return m.ListObjectsV2Func(ctx, params, optFns...)
	}
	return nil, nil
}

func (m *mockS3APIClient) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	if m.HeadObjectFunc != nil {
		return m.HeadObjectFunc(ctx, params, optFns...)
	}
	return nil, nil
}

var _ s3API = (*mockS3APIClient)(nil)

func TestClient_GetObject(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{
		Bucket: "test-bucket",
	}

	t.Run("successful get object", func(t *testing.T) {
		mockAPI := &mockS3APIClient{
			GetObjectFunc: func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
				if *params.Bucket != cfg.Bucket {
					return nil, fmt.Errorf("expected bucket %s, got %s", cfg.Bucket, *params.Bucket)
				}
				if *params.Key != "test-key" {
					return nil, fmt.Errorf("expected key test-key, got %s", *params.Key)
				}
				return &s3.GetObjectOutput{
					Body: io.NopCloser(strings.NewReader("s3 object content")),
				}, nil
			},
		}
		client := &Client{s3Client: mockAPI, config: cfg}

		body, err := client.GetObject(ctx, "test-key")
		if err != nil {
			t.Fatalf("GetObject() error = %v, want nil", err)
		}
		defer func() {
			if err := body.Close(); err != nil {
				t.Errorf("failed to close body: %v", err)
			}
		}()

		content, readErr := io.ReadAll(body)
		if readErr != nil {
			t.Fatalf("Failed to read object body: %v", readErr)
		}
		if string(content) != "s3 object content" {
			t.Errorf("GetObject() body content = %s, want \"s3 object content\"", string(content))
		}
	})

	t.Run("s3 GetObject returns an error", func(t *testing.T) {
		expectedErr := fmt.Errorf("s3 api error")
		mockAPI := &mockS3APIClient{
			GetObjectFunc: func(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
				return nil, expectedErr
			},
		}
		client := &Client{s3Client: mockAPI, config: cfg}

		_, err := client.GetObject(ctx, "another-key")
		if err == nil {
			t.Fatal("GetObject() error = nil, want error")
		}
		if !errors.Is(err, expectedErr) { // Use errors.Is for wrapped errors if any
			t.Errorf("GetObject() error = %v, want %v", err, expectedErr)
		}
	})

}

func TestClient_PutObject(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{
		Bucket: "test-put-bucket",
	}

	t.Run("successful put object", func(t *testing.T) {
		testContent := "this is test content for put"
		var capturedKey string
		var capturedBucket string
		var capturedBodyContent []byte

		mockAPI := &mockS3APIClient{
			PutObjectFunc: func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
				capturedBucket = *params.Bucket
				capturedKey = *params.Key

				bodyBytes, err := io.ReadAll(params.Body)
				if err != nil {
					return nil, fmt.Errorf("mock failed to read body: %w", err)
				}
				capturedBodyContent = bodyBytes

				return &s3.PutObjectOutput{
					ETag: aws.String("test-etag"),
				}, nil
			},
		}
		client := &Client{s3Client: mockAPI, config: cfg}

		err := client.PutObject(ctx, "upload-test-key", strings.NewReader(testContent))
		if err != nil {
			t.Fatalf("PutObject() error = %v, want nil", err)
		}

		if capturedBucket != cfg.Bucket {
			t.Errorf("PutObject() sent bucket = %s, want %s", capturedBucket, cfg.Bucket)
		}
		if capturedKey != "upload-test-key" {
			t.Errorf("PutObject() sent key = %s, want \"upload-test-key\"", capturedKey)
		}
		if string(capturedBodyContent) != testContent {
			t.Errorf("PutObject() sent body = %s, want %s", string(capturedBodyContent), testContent)
		}
	})

	t.Run("s3 PutObject returns an error", func(t *testing.T) {
		expectedErr := fmt.Errorf("s3 api put error")
		mockAPI := &mockS3APIClient{
			PutObjectFunc: func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
				// Consume the body to mimic S3 behavior even on error, preventing potential resource leaks if body is a file
				_, _ = io.ReadAll(params.Body)
				return nil, expectedErr
			},
		}
		client := &Client{s3Client: mockAPI, config: cfg}

		err := client.PutObject(ctx, "error-key", strings.NewReader("some data"))
		if err == nil {
			t.Fatal("PutObject() error = nil, want error")
		}
		if !errors.Is(err, expectedErr) {
			t.Errorf("PutObject() error = %v, want %v", err, expectedErr)
		}
	})

}

func TestClient_ResolveBackupKey(t *testing.T) {
	ctx := context.Background()

	t.Run("filename provided in config", func(t *testing.T) {
		providedFilename := "specific-backup.snap"
		cfg := &Config{
			Bucket:   "resolve-bucket",
			FileName: providedFilename,
		}

		t.Run("HeadObject success", func(t *testing.T) {
			mockAPI := &mockS3APIClient{
				HeadObjectFunc: func(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
					if *params.Bucket != cfg.Bucket {
						return nil, fmt.Errorf("expected bucket %s, got %s", cfg.Bucket, *params.Bucket)
					}
					if *params.Key != providedFilename {
						return nil, fmt.Errorf("expected key %s, got %s", providedFilename, *params.Key)
					}
					return &s3.HeadObjectOutput{}, nil
				},
			}
			client := &Client{s3Client: mockAPI, config: cfg}
			key, err := client.ResolveBackupKey(ctx)
			if err != nil {
				t.Fatalf("ResolveBackupKey() error = %v, want nil", err)
			}
			if key != providedFilename {
				t.Errorf("ResolveBackupKey() key = %s, want %s", key, providedFilename)
			}
		})

		t.Run("HeadObject returns NoSuchKey error", func(t *testing.T) {
			mockAPI := &mockS3APIClient{
				HeadObjectFunc: func(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
					return nil, &types.NoSuchKey{Message: aws.String("test no such key")}
				},
			}
			client := &Client{s3Client: mockAPI, config: cfg}
			_, err := client.ResolveBackupKey(ctx)
			if err == nil {
				t.Fatal("ResolveBackupKey() error = nil, want error")
			}

			expectedPhrasePart1 := "the specified backup file"
			expectedPhrasePart2 := fmt.Sprintf("'%q' was not found in bucket '%s'", providedFilename, cfg.Bucket)

			if !strings.Contains(err.Error(), expectedPhrasePart1) || !strings.Contains(err.Error(), expectedPhrasePart2) {
				t.Errorf("ResolveBackupKey() error = %q, want error containing %q and %q", err.Error(), expectedPhrasePart1, expectedPhrasePart2)
			}
		})

		t.Run("HeadObject returns generic S3 error", func(t *testing.T) {
			expectedErr := fmt.Errorf("generic S3 head error")
			mockAPI := &mockS3APIClient{
				HeadObjectFunc: func(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
					return nil, expectedErr
				},
			}
			client := &Client{s3Client: mockAPI, config: cfg}
			_, err := client.ResolveBackupKey(ctx)
			if !errors.Is(err, expectedErr) {
				t.Errorf("ResolveBackupKey() error = %v, want %v", err, expectedErr)
			}
		})
	})

	t.Run("filename not provided, find latest", func(t *testing.T) {
		cfg := &Config{
			Bucket: "resolve-latest-bucket",
		}

		t.Run("found latest .snap file", func(t *testing.T) {
			now := time.Now()
			oldTime := now.Add(-1 * time.Hour)
			latestTime := now.Add(-10 * time.Minute)
			expectedKey := "backup-latest.snap"

			mockAPI := &mockS3APIClient{
				ListObjectsV2Func: func(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
					if *params.Bucket != cfg.Bucket {
						return nil, fmt.Errorf("expected bucket %s, got %s", cfg.Bucket, *params.Bucket)
					}
					return &s3.ListObjectsV2Output{
						Contents: []types.Object{
							{Key: aws.String("backup-old.snap"), LastModified: aws.Time(oldTime)},
							{Key: aws.String("other-file.txt"), LastModified: aws.Time(now)},
							{Key: aws.String(expectedKey), LastModified: aws.Time(latestTime)},
							{Key: aws.String("backup-ancient.snap"), LastModified: aws.Time(oldTime.Add(-1 * time.Hour))},
						},
					}, nil
				},
			}
			client := &Client{s3Client: mockAPI, config: cfg}
			key, err := client.ResolveBackupKey(ctx)
			if err != nil {
				t.Fatalf("ResolveBackupKey() error = %v, want nil", err)
			}
			if key != expectedKey {
				t.Errorf("ResolveBackupKey() key = %s, want %s", key, expectedKey)
			}
		})

		t.Run("no .snap files found", func(t *testing.T) {
			mockAPI := &mockS3APIClient{
				ListObjectsV2Func: func(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
					return &s3.ListObjectsV2Output{
						Contents: []types.Object{
							{Key: aws.String("file1.txt"), LastModified: aws.Time(time.Now())},
							{Key: aws.String("another.dat"), LastModified: aws.Time(time.Now())},
						},
					}, nil
				},
			}
			client := &Client{s3Client: mockAPI, config: cfg}
			_, err := client.ResolveBackupKey(ctx)
			if err == nil {
				t.Fatal("ResolveBackupKey() error = nil, want error")
			}
			expectedErrorSubstring := "no suitable backup files were found"
			if !strings.Contains(err.Error(), expectedErrorSubstring) {
				t.Errorf("ResolveBackupKey() error = %v, want error containing %q", err, expectedErrorSubstring)
			}
		})

		t.Run("S3 ListObjectsV2 returns an error", func(t *testing.T) {
			expectedErr := fmt.Errorf("s3 list error")
			mockAPI := &mockS3APIClient{
				ListObjectsV2Func: func(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
					return nil, expectedErr
				},
			}
			client := &Client{s3Client: mockAPI, config: cfg}
			_, err := client.ResolveBackupKey(ctx)
			if !errors.Is(err, expectedErr) {
				t.Errorf("ResolveBackupKey() error = %v, want %v", err, expectedErr)
			}
		})

		t.Run("pagination to find latest .snap file", func(t *testing.T) {
			now := time.Now()
			latestTime := now.Add(-5 * time.Minute)
			expectedKey := "backup-page2-latest.snap"
			callCount := 0

			mockAPI := &mockS3APIClient{
				ListObjectsV2Func: func(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
					callCount++
					switch callCount {
					case 1:
						return &s3.ListObjectsV2Output{
							Contents: []types.Object{
								{Key: aws.String("backup-page1-old.snap"), LastModified: aws.Time(now.Add(-1 * time.Hour))},
							},
							NextContinuationToken: aws.String("nexttoken"),
							IsTruncated:           aws.Bool(true),
						}, nil
					case 2:
						if params.ContinuationToken == nil || *params.ContinuationToken != "nexttoken" {
							return nil, fmt.Errorf("expected continuation token 'nexttoken', got %v", params.ContinuationToken)
						}
						return &s3.ListObjectsV2Output{
							Contents: []types.Object{
								{Key: aws.String(expectedKey), LastModified: aws.Time(latestTime)},
								{Key: aws.String("backup-page2-older.snap"), LastModified: aws.Time(latestTime.Add(-30 * time.Minute))},
							},
						}, nil
					default:
						return nil, fmt.Errorf("ListObjectsV2 called too many times (%d)", callCount)
					}
				},
			}
			client := &Client{s3Client: mockAPI, config: cfg}
			key, err := client.ResolveBackupKey(ctx)
			if err != nil {
				t.Fatalf("ResolveBackupKey() with pagination error = %v, want nil", err)
			}
			if key != expectedKey {
				t.Errorf("ResolveBackupKey() with pagination key = %s, want %s", key, expectedKey)
			}
			if callCount != 2 {
				t.Errorf("Expected ListObjectsV2 to be called 2 times for pagination, got %d", callCount)
			}
		})
	})
}
