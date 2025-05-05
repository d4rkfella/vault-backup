package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/d4rkfella/vault-backup/internal/pkg/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRestore_Success_SpecificFile(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)
	specificFilename := "backup-specific.snap"
	mockRestoreData := "mock-restore-content"
	mockRestoreDataSize := int64(len(mockRestoreData))

	s3Mock.On("HeadObject", ctx, specificFilename).Return(true, nil).Once()
	mockReadCloser := io.NopCloser(strings.NewReader(mockRestoreData))
	s3Mock.On("GetObject", ctx, specificFilename).Return(mockReadCloser, nil).Once()
	vaultMock.On("Restore", ctx, mock.Anything).Return(nil).Once()
	notifyMock.On("Notify", ctx, true, "restore", mock.AnythingOfType("time.Duration"), mockRestoreDataSize, nil, mock.AnythingOfType("map[string]string")).Return(nil).Once()

	err := Restore(ctx, vaultMock, s3Mock, notifyMock, specificFilename)

	require.NoError(t, err)
	vaultMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
	notifyMock.AssertExpectations(t)
}

func TestRestore_Success_FindLatest(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)
	latestFilename := "backup-latest.snap"
	mockRestoreData := "mock-restore-content-latest"
	mockRestoreDataSize := int64(len(mockRestoreData))

	s3Mock.On("FindLatestSnapshotKey", ctx).Return(latestFilename, nil).Once()
	mockReadCloser := io.NopCloser(strings.NewReader(mockRestoreData))
	s3Mock.On("GetObject", ctx, latestFilename).Return(mockReadCloser, nil).Once()
	vaultMock.On("Restore", ctx, mock.Anything).Return(nil).Once()
	notifyMock.On("Notify", ctx, true, "restore", mock.AnythingOfType("time.Duration"), mockRestoreDataSize, nil, mock.MatchedBy(func(m map[string]string) bool { return m["File"] == latestFilename })).Return(nil).Once()

	err := Restore(ctx, vaultMock, s3Mock, notifyMock, "")

	require.NoError(t, err)
	vaultMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
	notifyMock.AssertExpectations(t)
}

func TestRestore_Fail_S3GetObject(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)
	specificFilename := "backup-specific-fail.snap"
	expectedError := errors.New("s3 get object failed")

	s3Mock.On("HeadObject", ctx, specificFilename).Return(true, nil).Once()
	s3Mock.On("GetObject", ctx, specificFilename).Return(nil, expectedError).Once()
	notifyMock.On("Notify", ctx,
		false,
		"restore",
		mock.AnythingOfType("time.Duration"),
		mock.AnythingOfType("int64"),
		mock.MatchedBy(func(err error) bool {
			return errors.Is(err, expectedError)
		}),
		mock.AnythingOfType("map[string]string"),
	).Return(nil).Once()

	err := Restore(ctx, vaultMock, s3Mock, notifyMock, specificFilename)

	require.Error(t, err)
	assert.ErrorContains(t, err, expectedError.Error())
	vaultMock.AssertNotCalled(t, "Restore")
	s3Mock.AssertExpectations(t)
	notifyMock.AssertExpectations(t)
}

func TestRestore_Fail_VaultRestore(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)
	specificFilename := "backup-specific-ok.snap"
	mockRestoreData := "mock-restore-content-bad"
	mockRestoreDataSize := int64(len(mockRestoreData))
	expectedError := errors.New("vault restore api failed")

	s3Mock.On("HeadObject", ctx, specificFilename).Return(true, nil).Once()
	mockReadCloser := io.NopCloser(strings.NewReader(mockRestoreData))
	s3Mock.On("GetObject", ctx, specificFilename).Return(mockReadCloser, nil).Once()
	vaultMock.On("Restore", ctx, mock.Anything).Return(expectedError).Once()
	notifyMock.On("Notify", ctx,
		false,
		"restore",
		mock.AnythingOfType("time.Duration"),
		mockRestoreDataSize,
		mock.MatchedBy(func(err error) bool {
			return errors.Is(err, expectedError)
		}),
		mock.AnythingOfType("map[string]string"),
	).Return(nil).Once()

	err := Restore(ctx, vaultMock, s3Mock, notifyMock, specificFilename)

	require.Error(t, err)
	assert.ErrorIs(t, err, expectedError)
	vaultMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
	notifyMock.AssertExpectations(t)
}

func TestRestore_Fail_FindLatest_Error(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)
	expectedError := errors.New("s3 find latest failed")

	s3Mock.On("FindLatestSnapshotKey", ctx).Return("", expectedError).Once()
	notifyMock.On("Notify", ctx,
		false,
		"restore",
		mock.AnythingOfType("time.Duration"),
		int64(0),
		mock.MatchedBy(func(err error) bool { return err != nil && strings.Contains(err.Error(), expectedError.Error()) }),
		mock.AnythingOfType("map[string]string"),
	).Return(nil).Once()

	err := Restore(ctx, vaultMock, s3Mock, notifyMock, "")

	require.Error(t, err)
	assert.ErrorContains(t, err, expectedError.Error())
	s3Mock.AssertExpectations(t)
	notifyMock.AssertExpectations(t)
	vaultMock.AssertNotCalled(t, "Restore")
	s3Mock.AssertNotCalled(t, "GetObject")
}

func TestRestore_Fail_FindLatest_NoFiles(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)
	notFoundError := s3.ErrNoBackupFilesFound
	expectedErrorMsg := s3.ErrNoBackupFilesFound.Error()

	s3Mock.On("FindLatestSnapshotKey", ctx).Return("", notFoundError).Once()
	notifyMock.On("Notify", ctx,
		false,
		"restore",
		mock.AnythingOfType("time.Duration"),
		int64(0),
		mock.MatchedBy(func(err error) bool {
			return errors.Is(err, notFoundError)
		}),
		mock.AnythingOfType("map[string]string"),
	).Return(nil).Once()

	err := Restore(ctx, vaultMock, s3Mock, notifyMock, "")

	require.Error(t, err)
	assert.ErrorContains(t, err, expectedErrorMsg)
	s3Mock.AssertExpectations(t)
	notifyMock.AssertExpectations(t)
	vaultMock.AssertNotCalled(t, "Restore")
	s3Mock.AssertNotCalled(t, "GetObject")
}

func TestRestore_Fail_HeadObject_NotFound(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)
	specificFilename := "backup-nonexistent.snap"
	expectedErrorMsg := fmt.Sprintf("specified backup file %q not found", specificFilename)

	s3Mock.On("HeadObject", ctx, specificFilename).Return(false, nil).Once()
	notifyMock.On("Notify", ctx,
		false,
		"restore",
		mock.AnythingOfType("time.Duration"),
		int64(0),
		mock.MatchedBy(func(err error) bool { return err != nil && err.Error() == expectedErrorMsg }),
		mock.AnythingOfType("map[string]string"),
	).Return(nil).Once()

	err := Restore(ctx, vaultMock, s3Mock, notifyMock, specificFilename)

	require.Error(t, err)
	assert.EqualError(t, err, expectedErrorMsg)
	s3Mock.AssertExpectations(t)
	notifyMock.AssertExpectations(t)
	vaultMock.AssertNotCalled(t, "Restore")
	s3Mock.AssertNotCalled(t, "GetObject")
}

func TestRestore_Fail_HeadObject_Error(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)
	specificFilename := "backup-head-error.snap"
	expectedError := errors.New("s3 head object failed")

	s3Mock.On("HeadObject", ctx, specificFilename).Return(false, expectedError).Once()
	notifyMock.On("Notify", ctx,
		false,
		"restore",
		mock.AnythingOfType("time.Duration"),
		int64(0),
		mock.MatchedBy(func(err error) bool { return err != nil && strings.Contains(err.Error(), expectedError.Error()) }),
		mock.AnythingOfType("map[string]string"),
	).Return(nil).Once()

	err := Restore(ctx, vaultMock, s3Mock, notifyMock, specificFilename)

	require.Error(t, err)
	assert.ErrorContains(t, err, expectedError.Error())
	s3Mock.AssertExpectations(t)
	notifyMock.AssertExpectations(t)
	vaultMock.AssertNotCalled(t, "Restore")
	s3Mock.AssertNotCalled(t, "GetObject")
}

func TestRestore_Fail_Notification(t *testing.T) {
	ctx := context.Background()
	vaultMock := newMockVaultClient(t)
	s3Mock := new(mockS3Client)
	notifyMock := new(mockNotifyClient)
	specificFilename := "backup-notify-fail.snap"
	mockRestoreData := "mock-restore-data"
	mockRestoreDataSize := int64(len(mockRestoreData))
	notificationError := errors.New("pushover API error")

	s3Mock.On("HeadObject", ctx, specificFilename).Return(true, nil).Once()
	mockReadCloser := io.NopCloser(strings.NewReader(mockRestoreData))
	s3Mock.On("GetObject", ctx, specificFilename).Return(mockReadCloser, nil).Once()
	vaultMock.On("Restore", ctx, mock.Anything).Return(nil).Once()
	notifyMock.On("Notify", ctx,
		true,
		"restore",
		mock.AnythingOfType("time.Duration"),
		mockRestoreDataSize,
		nil,
		mock.AnythingOfType("map[string]string"),
	).Return(notificationError).Once()

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	err := Restore(ctx, vaultMock, s3Mock, notifyMock, specificFilename)

	if errClose := w.Close(); errClose != nil {
		t.Logf("Warning: closing stderr pipe writer failed: %v", errClose)
	}
	os.Stderr = oldStderr
	stderrBytes, _ := io.ReadAll(r)

	assert.NoError(t, err)
	assert.Contains(t, string(stderrBytes), "Warning: failed to send notification:")
	assert.Contains(t, string(stderrBytes), notificationError.Error())
	vaultMock.AssertExpectations(t)
	s3Mock.AssertExpectations(t)
	notifyMock.AssertExpectations(t)
}
