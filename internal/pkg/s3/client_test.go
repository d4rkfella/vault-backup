package s3

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockS3API struct {
	mock.Mock
}

var _ s3API = (*mockS3API)(nil)

func (m *mockS3API) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	args := m.Called(ctx, params)
	output, _ := args.Get(0).(*s3.PutObjectOutput)
	return output, args.Error(1)
}

func (m *mockS3API) GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	args := m.Called(ctx, params)
	output, _ := args.Get(0).(*s3.GetObjectOutput)
	return output, args.Error(1)
}

func (m *mockS3API) HeadObject(ctx context.Context, params *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	args := m.Called(ctx, params)
	output, _ := args.Get(0).(*s3.HeadObjectOutput)
	return output, args.Error(1)
}

func (m *mockS3API) ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	args := m.Called(ctx, params)
	output, _ := args.Get(0).(*s3.ListObjectsV2Output)
	return output, args.Error(1)
}

func TestPutObject_Success(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockS3API)
	cfg := &Config{Bucket: "test-bucket"}
	client := &Client{s3Client: mockAPI, config: cfg}
	key := "test-key"
	content := "test-content"
	reader := strings.NewReader(content)

	mockAPI.On("PutObject", mock.Anything,
		mock.MatchedBy(func(input *s3.PutObjectInput) bool {
			return *input.Bucket == cfg.Bucket && *input.Key == key
		})).Return(&s3.PutObjectOutput{}, nil).Once()

	err := client.PutObject(ctx, key, reader)

	require.NoError(t, err)
	mockAPI.AssertExpectations(t)
}

func TestPutObject_Failure(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockS3API)
	cfg := &Config{Bucket: "test-bucket"}
	client := &Client{s3Client: mockAPI, config: cfg}
	key := "test-key-fail"
	reader := strings.NewReader("test-fail")
	expectedError := errors.New("s3 put failed")

	mockAPI.On("PutObject", mock.Anything,
		mock.AnythingOfType("*s3.PutObjectInput")).Return(nil, expectedError).Once()

	err := client.PutObject(ctx, key, reader)

	require.Error(t, err)
	assert.EqualError(t, err, expectedError.Error())
	mockAPI.AssertExpectations(t)
}

func TestGetObject_Success(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockS3API)
	cfg := &Config{Bucket: "test-bucket"}
	client := &Client{s3Client: mockAPI, config: cfg}
	key := "test-key-get"
	expectedContent := "hello world"

	mockGetObjectOutput := &s3.GetObjectOutput{
		Body:          io.NopCloser(strings.NewReader(expectedContent)),
		ContentLength: aws.Int64(int64(len(expectedContent))),
	}
	mockAPI.On("GetObject", ctx, mock.MatchedBy(func(input *s3.GetObjectInput) bool {
		return *input.Bucket == cfg.Bucket && *input.Key == key
	})).Return(mockGetObjectOutput, nil).Once()

	bodyReader, err := client.GetObject(ctx, key)

	require.NoError(t, err)
	require.NotNil(t, bodyReader)
	defer func() {
		if err := bodyReader.Close(); err != nil {
			t.Logf("Warning: failed to close body reader in test: %v", err)
		}
	}()

	readBytes, readErr := io.ReadAll(bodyReader)
	require.NoError(t, readErr)
	assert.Equal(t, expectedContent, string(readBytes))
	mockAPI.AssertExpectations(t)
}

func TestGetObject_Failure(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockS3API)
	cfg := &Config{Bucket: "test-bucket"}
	client := &Client{s3Client: mockAPI, config: cfg}
	key := "test-key-get-fail"
	expectedError := errors.New("s3 get failed")

	mockAPI.On("GetObject", ctx, mock.AnythingOfType("*s3.GetObjectInput")).Return(nil, expectedError).Once()

	bodyReader, err := client.GetObject(ctx, key)

	require.Error(t, err)
	assert.ErrorContains(t, err, expectedError.Error())
	assert.Nil(t, bodyReader)
	mockAPI.AssertExpectations(t)
}

func TestHeadObject_Success(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockS3API)
	cfg := &Config{Bucket: "test-bucket"}
	client := &Client{s3Client: mockAPI, config: cfg}
	key := "test-key-head"

	mockAPI.On("HeadObject", ctx, mock.MatchedBy(func(input *s3.HeadObjectInput) bool {
		return *input.Bucket == cfg.Bucket && *input.Key == key
	})).Return(&s3.HeadObjectOutput{}, nil).Once()

	exists, err := client.HeadObject(ctx, key)

	require.NoError(t, err)
	assert.True(t, exists)
	mockAPI.AssertExpectations(t)
}

func TestHeadObject_NotFound(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockS3API)
	cfg := &Config{Bucket: "test-bucket"}
	client := &Client{s3Client: mockAPI, config: cfg}
	key := "test-key-head-notfound"
	var notFoundErr *types.NoSuchKey

	mockAPI.On("HeadObject", ctx, mock.MatchedBy(func(input *s3.HeadObjectInput) bool {
		return *input.Bucket == cfg.Bucket && *input.Key == key
	})).Return(nil, notFoundErr).Once()

	exists, err := client.HeadObject(ctx, key)

	require.NoError(t, err)
	assert.False(t, exists)
	mockAPI.AssertExpectations(t)
}

func TestHeadObject_OtherFailure(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockS3API)
	cfg := &Config{Bucket: "test-bucket"}
	client := &Client{s3Client: mockAPI, config: cfg}
	key := "test-key-head-fail"
	expectedError := errors.New("s3 head failed")

	mockAPI.On("HeadObject", ctx, mock.AnythingOfType("*s3.HeadObjectInput")).Return(nil, expectedError).Once()

	exists, err := client.HeadObject(ctx, key)

	require.Error(t, err)
	assert.ErrorContains(t, err, expectedError.Error())
	assert.False(t, exists)
	mockAPI.AssertExpectations(t)
}

func TestFindLatestSnapshotKey_Success_SinglePage(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockS3API)
	cfg := &Config{Bucket: "test-bucket"}
	client := &Client{s3Client: mockAPI, config: cfg}

	now := time.Now()
	expectedKey := "backup-3.snap"

	mockOutput := &s3.ListObjectsV2Output{
		Contents: []types.Object{
			{Key: aws.String("backup-1.snap"), LastModified: aws.Time(now.Add(-2 * time.Hour))},
			{Key: aws.String("other-file.txt"), LastModified: aws.Time(now.Add(-1 * time.Hour))},
			{Key: aws.String(expectedKey), LastModified: aws.Time(now)},
			{Key: aws.String("backup-2.snap"), LastModified: aws.Time(now.Add(-3 * time.Hour))},
		},
		IsTruncated:           aws.Bool(false),
		NextContinuationToken: nil,
	}

	mockAPI.On("ListObjectsV2", ctx, mock.MatchedBy(func(input *s3.ListObjectsV2Input) bool {
		return *input.Bucket == cfg.Bucket && input.ContinuationToken == nil
	})).Return(mockOutput, nil).Once()

	latestKey, err := client.FindLatestSnapshotKey(ctx)

	require.NoError(t, err)
	assert.Equal(t, expectedKey, latestKey)
	mockAPI.AssertExpectations(t)
}

func TestFindLatestSnapshotKey_Success_MultiPage(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockS3API)
	cfg := &Config{Bucket: "test-bucket"}
	client := &Client{s3Client: mockAPI, config: cfg}

	now := time.Now()
	expectedKey := "backup-page2-latest.snap"

	mockOutput1 := &s3.ListObjectsV2Output{
		Contents: []types.Object{
			{Key: aws.String("backup-page1-a.snap"), LastModified: aws.Time(now.Add(-5 * time.Hour))},
			{Key: aws.String("backup-page1-b.snap"), LastModified: aws.Time(now.Add(-4 * time.Hour))},
		},
		IsTruncated:           aws.Bool(true),
		NextContinuationToken: aws.String("token1"),
	}

	mockOutput2 := &s3.ListObjectsV2Output{
		Contents: []types.Object{
			{Key: aws.String(expectedKey), LastModified: aws.Time(now)},
			{Key: aws.String("backup-page2-early.snap"), LastModified: aws.Time(now.Add(-6 * time.Hour))},
		},
		IsTruncated:           aws.Bool(false),
		NextContinuationToken: nil,
	}

	mockAPI.On("ListObjectsV2", ctx, mock.MatchedBy(func(input *s3.ListObjectsV2Input) bool {
		return *input.Bucket == cfg.Bucket && input.ContinuationToken == nil
	})).Return(mockOutput1, nil).Once()

	mockAPI.On("ListObjectsV2", ctx, mock.MatchedBy(func(input *s3.ListObjectsV2Input) bool {
		return *input.Bucket == cfg.Bucket && input.ContinuationToken != nil && *input.ContinuationToken == "token1"
	})).Return(mockOutput2, nil).Once()

	latestKey, err := client.FindLatestSnapshotKey(ctx)

	require.NoError(t, err)
	assert.Equal(t, expectedKey, latestKey)
	mockAPI.AssertExpectations(t)
}

func TestFindLatestSnapshotKey_NoSnapshotsFound(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockS3API)
	cfg := &Config{Bucket: "test-bucket"}
	client := &Client{s3Client: mockAPI, config: cfg}

	mockOutput := &s3.ListObjectsV2Output{
		Contents: []types.Object{
			{Key: aws.String("file1.txt"), LastModified: aws.Time(time.Now())},
			{Key: aws.String("image.jpg"), LastModified: aws.Time(time.Now())},
		},
		IsTruncated:           aws.Bool(false),
		NextContinuationToken: nil,
	}

	mockAPI.On("ListObjectsV2", ctx, mock.AnythingOfType("*s3.ListObjectsV2Input")).Return(mockOutput, nil).Once()

	latestKey, err := client.FindLatestSnapshotKey(ctx)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoBackupFilesFound)
	assert.Empty(t, latestKey)
	mockAPI.AssertExpectations(t)
}

func TestFindLatestSnapshotKey_EmptyBucket(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockS3API)
	cfg := &Config{Bucket: "test-bucket"}
	client := &Client{s3Client: mockAPI, config: cfg}

	mockOutput := &s3.ListObjectsV2Output{
		Contents:              []types.Object{},
		IsTruncated:           aws.Bool(false),
		NextContinuationToken: nil,
	}

	mockAPI.On("ListObjectsV2", ctx, mock.AnythingOfType("*s3.ListObjectsV2Input")).Return(mockOutput, nil).Once()

	latestKey, err := client.FindLatestSnapshotKey(ctx)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoBackupFilesFound)
	assert.Empty(t, latestKey)
	mockAPI.AssertExpectations(t)
}

func TestFindLatestSnapshotKey_ListError(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockS3API)
	cfg := &Config{Bucket: "test-bucket"}
	client := &Client{s3Client: mockAPI, config: cfg}
	expectedError := errors.New("s3 list objects failed")

	mockAPI.On("ListObjectsV2", ctx, mock.AnythingOfType("*s3.ListObjectsV2Input")).Return(nil, expectedError).Once()

	latestKey, err := client.FindLatestSnapshotKey(ctx)

	require.Error(t, err)
	assert.ErrorContains(t, err, expectedError.Error())
	assert.Empty(t, latestKey)
	mockAPI.AssertExpectations(t)
}

func TestNewClient(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{
		Region: "us-east-1",
		Bucket: "test-bucket",
	}

	client, err := NewClient(ctx, cfg)

	if err != nil {
		t.Logf("NewClient failed as expected (likely missing credentials): %v", err)
		assert.Nil(t, client, "Client should be nil when NewClient fails")
	} else {
		t.Logf("NewClient succeeded (credentials might be present in environment)")
		require.NotNil(t, client, "Client is nil despite NewClient succeeding")
		assert.NotNil(t, client.s3Client, "Client s3Client field is nil after successful NewClient")
		assert.Equal(t, cfg, client.config, "Client config field does not match input after successful NewClient")
	}
}
