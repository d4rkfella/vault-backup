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

func TestRestoreCommand_Success(t *testing.T) {
	viper.Reset()

	vaultAddr := "http://mock-vault:8200"
	vaultToken := "mock-token"
	s3Bucket := "mock-bucket"
	s3Region := "mock-region"
	s3Filename := "backup-to-restore.snap"
	s3AccessKey := "mock-access-key"
	s3SecretKey := "mock-secret-key"

	viper.Set("vault_address", vaultAddr)
	viper.Set("vault_token", vaultToken)
	viper.Set("s3_bucket", s3Bucket)
	viper.Set("s3_region", s3Region)
	viper.Set("s3_filename", s3Filename)
	viper.Set("s3_access_key", s3AccessKey)
	viper.Set("s3_secret_key", s3SecretKey)

	var receivedVaultClient app.VaultClient
	var receivedS3Client app.S3Client
	var receivedNotifyClient app.NotifyClient
	mockRestoreCalled := false

	originalRunRestore := runRestore
	runRestore = func(ctx context.Context, vc app.VaultClient, sc app.S3Client, nc app.NotifyClient) error {
		mockRestoreCalled = true
		receivedVaultClient = vc
		receivedS3Client = sc
		receivedNotifyClient = nc
		return nil
	}
	defer func() { runRestore = originalRunRestore }()

	output, err := executeCommand(rootCmd, "restore")

	require.NoError(t, err, "Command execution failed: %s", output)
	assert.True(t, mockRestoreCalled, "Mock app.Restore was not called")
	assert.NotNil(t, receivedVaultClient, "Vault client passed to app.Restore was nil")
	assert.NotNil(t, receivedS3Client, "S3 client passed to app.Restore was nil")
	assert.Nil(t, receivedNotifyClient, "Notify client passed to app.Restore should be nil")
}

func TestRestoreCommand_AppFailure(t *testing.T) {
	viper.Reset()

	vaultToken := "mock-token"
	s3Bucket := "mock-bucket"
	s3AccessKey := "mock-access-key"
	s3SecretKey := "mock-secret-key"

	viper.Set("vault_token", vaultToken)
	viper.Set("s3_bucket", s3Bucket)
	viper.Set("s3_access_key", s3AccessKey)
	viper.Set("s3_secret_key", s3SecretKey)

	expectedError := errors.New("restore failed in app layer")
	originalRunRestore := runRestore
	runRestore = func(ctx context.Context, vc app.VaultClient, sc app.S3Client, nc app.NotifyClient) error {
		return expectedError
	}
	defer func() { runRestore = originalRunRestore }()

	_, err := executeCommand(rootCmd, "restore")

	require.Error(t, err, "Command should have returned an error")
	assert.ErrorIs(t, err, expectedError, "Expected error from app layer to be returned")
}
