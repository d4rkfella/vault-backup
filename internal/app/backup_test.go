package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func createMinimalSnapshotBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzipWriter)
	filesToAdd := map[string][]byte{
		"SHA256SUMS":        []byte(""),
		"SHA256SUMS.sealed": []byte(""),
	}
	for name, content := range filesToAdd {
		hdr := &tar.Header{
			Name: name, Mode: 0600, Size: int64(len(content)), ModTime: time.Now(),
		}
		err := tarWriter.WriteHeader(hdr)
		require.NoError(t, err, "Failed to write tar header for %s", name)
		_, err = tarWriter.Write(content)
		require.NoError(t, err, "Failed to write tar content for %s", name)
	}
	err := tarWriter.Close()
	require.NoError(t, err, "Failed to close tar writer")
	err = gzipWriter.Close()
	require.NoError(t, err, "Failed to close gzip writer")
	return buf.Bytes()
}

func createInvalidSnapshotBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzipWriter)
	filesToAdd := map[string][]byte{
		"some_data.sealed": []byte("sealed data content"),
	}
	for name, content := range filesToAdd {
		hdr := &tar.Header{
			Name: name, Mode: 0600, Size: int64(len(content)), ModTime: time.Now(),
		}
		err := tarWriter.WriteHeader(hdr)
		require.NoError(t, err, "Failed to write tar header for %s", name)
		_, err = tarWriter.Write(content)
		require.NoError(t, err, "Failed to write tar content for %s", name)
	}
	err := tarWriter.Close()
	require.NoError(t, err, "Failed to close tar writer")
	err = gzipWriter.Close()
	require.NoError(t, err, "Failed to close gzip writer")
	return buf.Bytes()
}

type mockVaultClient struct {
	mock.Mock
	testingT *testing.T
}

var _ VaultClient = (*mockVaultClient)(nil)

func newMockVaultClient(t *testing.T) *mockVaultClient {
	return &mockVaultClient{testingT: t}
}

func (m *mockVaultClient) Backup(ctx context.Context, w io.Writer) error {
	args := m.Called(ctx, w)
	if args.Error(0) == nil {
		snapshotBytes := createMinimalSnapshotBytes(m.testingT)
		_, err := w.Write(snapshotBytes)
		if err != nil {
			return fmt.Errorf("mock write error: %w", err)
		}
	}
	return args.Error(0)
}

func (m *mockVaultClient) Restore(ctx context.Context, r io.Reader) error {
	_, _ = io.ReadAll(r)
	args := m.Called(ctx, r)
	return args.Error(0)
}

type mockS3Client struct {
	mock.Mock
}

var _ S3Client = (*mockS3Client)(nil)

func (m *mockS3Client) PutObject(ctx context.Context, key string, r io.Reader) error {
	args := m.Called(ctx, key, r)
	return args.Error(0)
}

func (m *mockS3Client) GetObject(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	args := m.Called(ctx, key)
	body, _ := args.Get(0).(io.ReadCloser)
	size, _ := args.Get(1).(int64)
	err := args.Error(2)
	return body, size, err
}

func (m *mockS3Client) GetObjectMetadata(ctx context.Context, key string) (int64, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(int64), args.Error(1)
}

func (m *mockS3Client) ResolveBackupKey(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

type mockNotifyClient struct {
	mock.Mock
}

var _ NotifyClient = (*mockNotifyClient)(nil)

func (m *mockNotifyClient) Notify(ctx context.Context, success bool, opType string, duration time.Duration, sizeBytes int64, err error, details map[string]string) error {
	args := m.Called(ctx, success, opType, duration, sizeBytes, err, details)
	return args.Error(0)
}

func TestBackup_Success_WithNotification_WithRevoke(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)

	vaultMock.On("Backup", ctx, mock.AnythingOfType("*bytes.Buffer")).Return(nil).Once()
	s3Mock.On("PutObject", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("*bytes.Reader")).Return(nil).Once()
	notifyMock.On("Notify", ctx,
		true,
		"backup",
		mock.AnythingOfType("time.Duration"),
		mock.AnythingOfType("int64"),
		nil,
		mock.AnythingOfType("map[string]string"),
	).Run(func(args mock.Arguments) {
		details := args.Get(6).(map[string]string)
		assert.Contains(t, details, "File")
	}).Return(nil).Once()

	err := Backup(ctx, vaultMock, s3Mock, notifyMock)

	assert.NoError(t, err)
	vaultMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
	notifyMock.AssertExpectations(t)
}

func TestBackup_Success_NoNotification_NoRevoke(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	var notifyMock NotifyClient = nil

	vaultMock.On("Backup", ctx, mock.AnythingOfType("*bytes.Buffer")).Return(nil).Once()
	s3Mock.On("PutObject", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("*bytes.Reader")).Return(nil).Once()

	err := Backup(ctx, vaultMock, s3Mock, notifyMock)

	assert.NoError(t, err)
	vaultMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
}

func TestBackup_VaultBackupFails(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)
	expectedError := errors.New("vault backup api error")

	vaultMock.On("Backup", ctx, mock.AnythingOfType("*bytes.Buffer")).Return(expectedError).Once()
	notifyMock.On("Notify", ctx,
		false,
		"backup",
		mock.AnythingOfType("time.Duration"),
		int64(0),
		mock.MatchedBy(func(err error) bool {
			return errors.Is(err, expectedError)
		}),
		mock.AnythingOfType("map[string]string"),
	).Return(nil).Once()

	err := Backup(ctx, vaultMock, s3Mock, notifyMock)

	assert.Error(t, err)
	assert.ErrorIs(t, err, expectedError)
	vaultMock.AssertExpectations(t)
	s3Mock.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything, mock.Anything)
	notifyMock.AssertExpectations(t)
}

func TestBackup_S3UploadFails(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)
	expectedError := errors.New("s3 put error")

	vaultMock.On("Backup", ctx, mock.AnythingOfType("*bytes.Buffer")).Return(nil).Once()
	s3Mock.On("PutObject", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("*bytes.Reader")).Return(expectedError).Once()
	notifyMock.On("Notify", ctx,
		false,
		"backup",
		mock.AnythingOfType("time.Duration"),
		mock.AnythingOfType("int64"),
		mock.MatchedBy(func(err error) bool {
			return errors.Is(err, expectedError)
		}),
		mock.AnythingOfType("map[string]string"),
	).Return(nil).Once()

	err := Backup(ctx, vaultMock, s3Mock, notifyMock)

	assert.Error(t, err)
	assert.ErrorIs(t, err, expectedError)
	vaultMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
	notifyMock.AssertExpectations(t)
}

func TestBackup_VerifyChecksumsFails(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)
	expectedErrorMsg := "SHA256SUMS file not found"

	vaultMock.On("Backup", ctx, mock.AnythingOfType("*bytes.Buffer")).Run(func(args mock.Arguments) {
		w := args.Get(1).(io.Writer)
		invalidBytes := createInvalidSnapshotBytes(t)
		_, err := w.Write(invalidBytes)
		require.NoError(t, err)
	}).Return(nil).Once()

	notifyMock.On("Notify", ctx,
		false,
		"backup",
		mock.AnythingOfType("time.Duration"),
		mock.AnythingOfType("int64"),
		mock.MatchedBy(func(err error) bool { return err != nil && strings.Contains(err.Error(), expectedErrorMsg) }),
		mock.AnythingOfType("map[string]string"),
	).Return(nil).Once()

	err := Backup(ctx, vaultMock, s3Mock, notifyMock)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), expectedErrorMsg)
	vaultMock.AssertExpectations(t)
	s3Mock.AssertNotCalled(t, "PutObject", mock.Anything, mock.Anything, mock.Anything)
	notifyMock.AssertExpectations(t)
}

func TestBackup_NotificationFails(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)
	notificationError := errors.New("pushover api error")

	vaultMock.On("Backup", ctx, mock.AnythingOfType("*bytes.Buffer")).Return(nil).Once()
	s3Mock.On("PutObject", ctx, mock.AnythingOfType("string"), mock.AnythingOfType("*bytes.Reader")).Return(nil).Once()
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	notifyMock.On("Notify", ctx,
		true,
		"backup",
		mock.AnythingOfType("time.Duration"),
		mock.AnythingOfType("int64"),
		nil,
		mock.AnythingOfType("map[string]string"),
	).Return(notificationError).Once()

	err := Backup(ctx, vaultMock, s3Mock, notifyMock)

	if errClose := w.Close(); errClose != nil {
		t.Logf("Warning: closing stderr pipe writer failed: %v", errClose)
	}
	os.Stderr = oldStderr
	stderrBytes, _ := io.ReadAll(r)

	assert.NoError(t, err)
	assert.Contains(t, string(stderrBytes), "Warning: failed to send notification:", "Expected notification failure warning")
	assert.Contains(t, string(stderrBytes), notificationError.Error())

	vaultMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
	notifyMock.AssertExpectations(t)
}

func TestBackup_RevokeTokenFails(t *testing.T) {
	t.Skip("Skipping test as token revocation is removed")
}

func TestParseSHA256SUMS_Valid(t *testing.T) {
	content := []byte(`
ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb  file1.txt

187f0539196992306473c096a306e47014869f3a05d1612015e9eca90bf5ab75  some/other/file.bin 	
`)
	expected := map[string]string{
		"file1.txt":           "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
		"some/other/file.bin": "187f0539196992306473c096a306e47014869f3a05d1612015e9eca90bf5ab75",
	}

	result := parseSHA256SUMS(content)
	assert.Equal(t, expected, result)
}

func TestVerifyInternalChecksums_Success(t *testing.T) {
	tarData := createTestTarball(t, map[string]string{
		"SHA256SUMS": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb  file1.txt\n",
		"file1.txt":  "a",
	})

	valid, err := verifyInternalChecksums(tarData)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestVerifyInternalChecksums_ChecksumMismatch(t *testing.T) {
	tarData := createTestTarball(t, map[string]string{
		"SHA256SUMS": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  file1.txt\n",
		"file1.txt":  "a",
	})

	valid, err := verifyInternalChecksums(tarData)
	require.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "checksum mismatch for file1.txt")
}

func TestVerifyInternalChecksums_MissingFileInTar(t *testing.T) {
	tarData := createTestTarball(t, map[string]string{
		"SHA256SUMS": "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb  file1.txt\n",
	})

	valid, err := verifyInternalChecksums(tarData)
	require.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "file file1.txt listed in SHA256SUMS not found in archive")
}

func TestVerifyInternalChecksums_MissingSumsFile(t *testing.T) {
	tarData := createTestTarball(t, map[string]string{
		"file1.txt": "a",
	})

	valid, err := verifyInternalChecksums(tarData)
	require.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "SHA256SUMS file not found in the archive")
}

func TestVerifyInternalChecksums_InvalidSumsFileFormat(t *testing.T) {
	tarData := createTestTarball(t, map[string]string{
		"SHA256SUMS": "invalid format",
		"file1.txt":  "a",
	})

	valid, err := verifyInternalChecksums(tarData)
	require.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "file format listed in SHA256SUMS not found in archive")
}

func TestVerifyInternalChecksums_ReadErrorTar(t *testing.T) {

	invalidGzipData := []byte("not gzip data")
	valid, err := verifyInternalChecksums(invalidGzipData)
	require.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "gzip error")

	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	_, _ = gzipWriter.Write([]byte("corrupted tar data"))
	_ = gzipWriter.Close()
	corruptedTarData := buf.Bytes()
	valid, err = verifyInternalChecksums(corruptedTarData)
	require.Error(t, err)
	assert.False(t, valid)
	assert.Contains(t, err.Error(), "tar read error")
}

func createTestTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzipWriter := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gzipWriter)

	for name, content := range files {
		hdr := &tar.Header{
			Name:    name,
			Mode:    0600,
			Size:    int64(len(content)),
			ModTime: time.Now(),
		}
		err := tarWriter.WriteHeader(hdr)
		require.NoError(t, err)
		_, err = tarWriter.Write([]byte(content))
		require.NoError(t, err)
	}

	err := tarWriter.Close()
	require.NoError(t, err)
	err = gzipWriter.Close()
	require.NoError(t, err)
	return buf.Bytes()
}
