package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/d4rkfella/vault-backup/internal/app"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBackupCommand_Success(t *testing.T) {
	viper.Reset()

	vaultAddr := "http://mock-vault:8200"
	vaultToken := "mock-token"
	s3Bucket := "mock-bucket"
	s3Region := "mock-region"
	shouldRevoke := true

	viper.Set("vault_address", vaultAddr)
	viper.Set("vault_token", vaultToken)
	viper.Set("vault_revoke_token", shouldRevoke)
	viper.Set("s3_bucket", s3Bucket)
	viper.Set("s3_region", s3Region)

	var receivedVaultClient app.VaultClient
	var receivedS3Client app.S3Client
	var receivedNotifyClient app.NotifyClient
	var receivedRevokeFlag bool
	mockBackupCalled := false

	originalRunBackup := runBackup
	runBackup = func(ctx context.Context, vc app.VaultClient, sc app.S3Client, nc app.NotifyClient, revoke bool) error {
		mockBackupCalled = true
		receivedVaultClient = vc
		receivedS3Client = sc
		receivedNotifyClient = nc
		receivedRevokeFlag = revoke
		return nil
	}
	defer func() { runBackup = originalRunBackup }()

	output, err := executeCommand(rootCmd, "backup", "--revoke-token")

	require.NoError(t, err, "Command execution failed: %s", output)
	assert.True(t, mockBackupCalled, "Mock app.Backup was not called")
	assert.NotNil(t, receivedVaultClient, "Vault client passed to app.Backup was nil")
	assert.NotNil(t, receivedS3Client, "S3 client passed to app.Backup was nil")
	assert.Nil(t, receivedNotifyClient, "Notify client passed to app.Backup should be nil")
	assert.Equal(t, shouldRevoke, receivedRevokeFlag, "Revoke flag mismatch")
}

func TestBackupCommand_AppFailure(t *testing.T) {
	viper.Reset()

	vaultToken := "mock-token"
	s3Bucket := "mock-bucket"
	viper.Set("vault_token", vaultToken)
	viper.Set("s3_bucket", s3Bucket)

	expectedError := errors.New("backup failed in app layer")
	originalRunBackup := runBackup
	runBackup = func(ctx context.Context, vc app.VaultClient, sc app.S3Client, nc app.NotifyClient, revoke bool) error {
		return expectedError
	}
	defer func() { runBackup = originalRunBackup }()

	output, err := executeCommand(rootCmd, "backup")

	require.Error(t, err, "Expected error but command executed successfully")
	assert.ErrorIs(t, err, expectedError, "Expected error from app layer to be returned")
	assert.Contains(t, output, expectedError.Error(), "Expected error message not found in output")
}
