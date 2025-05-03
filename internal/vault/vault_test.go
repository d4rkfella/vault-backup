package vault

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/d4rkfella/vault-backup/internal/config"
	"github.com/d4rkfella/vault-backup/internal/logging"
	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// --- Mocks (Generated previously) --- //

type MockVaultAPIClient struct {
	mock.Mock
}

func (m *MockVaultAPIClient) Auth() AuthAPI {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(AuthAPI)
}

func (m *MockVaultAPIClient) Logical() LogicalAPI {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(LogicalAPI)
}

func (m *MockVaultAPIClient) Sys() SysAPI {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(SysAPI)
}

func (m *MockVaultAPIClient) SetToken(v string) {
	m.Called(v)
}

func (m *MockVaultAPIClient) Token() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockVaultAPIClient) Address() string {
	args := m.Called()
	return args.String(0)
}

type MockAuthAPI struct {
	mock.Mock
}

func (m *MockAuthAPI) Login(ctx context.Context, authMethod api.AuthMethod) (*api.Secret, error) {
	args := m.Called(ctx, authMethod)
	var secret *api.Secret
	if args.Get(0) != nil {
		secret = args.Get(0).(*api.Secret)
	}
	return secret, args.Error(1)
}

func (m *MockAuthAPI) Token() TokenAPI {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(TokenAPI)
}

type MockTokenAPI struct {
	mock.Mock
}

func (m *MockTokenAPI) LookupSelfWithContext(ctx context.Context) (*api.Secret, error) {
	args := m.Called(ctx)
	var secret *api.Secret
	if args.Get(0) != nil {
		secret = args.Get(0).(*api.Secret)
	}
	return secret, args.Error(1)
}

func (m *MockTokenAPI) RevokeSelfWithContext(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

type MockLogicalAPI struct {
	mock.Mock
}

func (m *MockLogicalAPI) ReadWithContext(ctx context.Context, path string) (*api.Secret, error) {
	args := m.Called(ctx, path)
	var secret *api.Secret
	if args.Get(0) != nil {
		secret = args.Get(0).(*api.Secret)
	}
	return secret, args.Error(1)
}

type MockSysAPI struct {
	mock.Mock
}

// Modified mock to allow injecting snapshot data for verification tests
var snapshotDataToInject []byte

func (m *MockSysAPI) RaftSnapshotWithContext(ctx context.Context, w io.Writer) error {
	args := m.Called(ctx, w)
	if err := args.Error(0); err == nil {
		// Use injected data if available, otherwise dummy data
		data := snapshotDataToInject
		if data == nil {
			data = []byte("dummy snapshot data") // Default dummy data
		}
		_, writeErr := w.Write(data)
		// Reset injected data after use
		snapshotDataToInject = nil
		return writeErr
	}
	// Reset injected data even on error
	snapshotDataToInject = nil
	return args.Error(0)
}

// --- Test Setup --- //

// Helper to create a dummy k8s token file
func createDummyK8sToken(t *testing.T) string {
	_ = t
	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "k8s_token")
	err := os.WriteFile(tokenPath, []byte("dummy-k8s-token"), 0600)
	require.NoError(t, err)
	return tokenPath
}

func setupTest(t *testing.T) (context.Context, *config.Config, *MockVaultAPIClient, *MockAuthAPI, *MockTokenAPI, *MockLogicalAPI, *MockSysAPI, func()) {
	_ = t // Prevent unused var error correctly
	// Create dummy token file path for K8s tests
	dummyTokenPath := createDummyK8sToken(t)

	// Basic config
	tmpDir := t.TempDir()
	cfg := &config.Config{
		VaultAddr:                "http://localhost:8200",
		VaultSecretPath:          "secret/data/app/creds",
		SnapshotPath:             filepath.Join(tmpDir, "test_snapshot.snap.gz"),
		LogLevel:                 "trace",
		VaultKubernetesTokenPath: dummyTokenPath, // Set the path in config
	}

	// Initialize logging (use console writer for tests)
	logging.Init(cfg.LogLevel) // Call directly, it has no return value
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	mockClient := new(MockVaultAPIClient)
	mockAuth := new(MockAuthAPI)
	mockToken := new(MockTokenAPI)
	mockLogical := new(MockLogicalAPI)
	mockSys := new(MockSysAPI)

	// Default setup: Client returns sub-mocks
	mockClient.On("Auth").Return(mockAuth)
	mockClient.On("Address").Return(cfg.VaultAddr)

	// --- Add dummy assertion to ensure mockAuth is seen as used --- //
	require.NotNil(t, mockAuth, "mockAuth should not be nil after creation")
	// -------------------------------------------------------------- //

	ctx := context.Background()

	// Teardown function
	teardown := func() {
		log.Logger = zerolog.Nop()
		snapshotDataToInject = nil
		// No need to clean up /var/run/secrets anymore
		// Temp dir created by createDummyK8sToken will be cleaned by t.TempDir()
	}

	return ctx, cfg, mockClient, mockAuth, mockToken, mockLogical, mockSys, teardown
}

// --- Helper Functions for Tests --- //

// Helper to create a valid tar archive in memory for verification tests
func createTestTarSnapshot(t *testing.T, files map[string][]byte, checksums map[string]string) []byte {
	_ = t // Prevent unused var error correctly
	buf := new(bytes.Buffer)
	tarWriter := tar.NewWriter(buf)

	// Write data files
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(content)),
		}
		require.NoError(t, tarWriter.WriteHeader(hdr))
		_, err := tarWriter.Write(content)
		require.NoError(t, err)
	}

	// Write checksum file
	var checksumContent strings.Builder
	for name, sum := range checksums {
		fmt.Fprintf(&checksumContent, "%s  %s\n", sum, name)
	}
	checksumBytes := []byte(checksumContent.String())
	chkHdr := &tar.Header{
		Name: "SHA256SUMS", // Vault uses this name now
		Mode: 0600,
		Size: int64(len(checksumBytes)),
	}
	require.NoError(t, tarWriter.WriteHeader(chkHdr))
	_, err := tarWriter.Write(checksumBytes)
	require.NoError(t, err)

	require.NoError(t, tarWriter.Close())
	return buf.Bytes()
}

// Helper for transient errors
type transientNetError struct{ error }

func (e transientNetError) Timeout() bool   { return true }
func (e transientNetError) Temporary() bool { return true }

// --- Test Cases --- //

func TestNewClient(t *testing.T) {
	_, cfg, mockClient, _, _, _, _, teardown := setupTest(t)
	defer teardown()

	// Success with mock
	client, err := NewClient(cfg, mockClient)
	assert.NoError(t, err)
	assert.NotNil(t, client)

	// Success with real client creation (requires Vault running or network mock)
	// For unit test, we rely on the mock path primarily.
	// If testing real client creation path:
	// mockClient = nil // Force real client creation
	// client, err = NewClient(cfg, mockClient)
	// assert.NoError(t, err) // This would fail if Vault isn't reachable
	// assert.NotNil(t, client)

	// Error: Nil config
	client, err = NewClient(nil, mockClient)
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "config cannot be nil")
}

func TestClient_Login_KubernetesSuccess(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, _, _, _, teardown := setupTest(t)
	defer teardown()

	cfg.VaultKubernetesRole = "test-role"
	_ = os.Unsetenv("VAULT_TOKEN") // Ignore error

	mockAuth.On("Login", ctx, mock.AnythingOfType("*kubernetes.KubernetesAuth")).Return(&api.Secret{}, nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	err = client.Login(ctx)
	assert.NoError(t, err)
	mockAuth.AssertExpectations(t)
	mockAuth.AssertNotCalled(t, "Token") // Verify Token() was not called for K8s auth
}

func TestClient_Login_TokenSuccess(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, _, teardown := setupTest(t)
	defer teardown()

	// Set VAULT_TOKEN
	_ = os.Setenv("VAULT_TOKEN", "test-token")        // Check errors if needed
	defer func() { _ = os.Unsetenv("VAULT_TOKEN") }() // Ignore error

	// Set up mock expectations
	mockClient.On("Address").Return("http://vault:8200").Once()
	mockClient.On("SetToken", "test-token").Return()
	mockClient.On("Token").Return("test-token").Once()
	mockAuth.On("Token").Return(mockToken).Once()
	mockToken.On("LookupSelfWithContext", mock.Anything).Return(&api.Secret{}, nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	err = client.Login(ctx)
	assert.NoError(t, err)
}

func TestClient_Login_K8sRetrySuccess(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, _, _, _, teardown := setupTest(t)
	defer teardown()

	cfg.VaultKubernetesRole = "test-role"
	_ = os.Unsetenv("VAULT_TOKEN") // Ignore error

	transientErr := transientNetError{errors.New("network timeout")}
	mockAuth.On("Login", mock.Anything, mock.AnythingOfType("*kubernetes.KubernetesAuth")).Return(nil, transientErr).Once()
	mockAuth.On("Login", mock.Anything, mock.AnythingOfType("*kubernetes.KubernetesAuth")).Return(&api.Secret{}, nil).Once() // Success on retry

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	err = client.Login(ctx)
	assert.NoError(t, err)
	mockAuth.AssertExpectations(t)
	mockAuth.AssertNotCalled(t, "Token") // Verify Token() was not called for K8s auth
}

func TestClient_Login_TokenRetrySuccess(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, _, teardown := setupTest(t)
	defer teardown()

	// Set VAULT_TOKEN
	_ = os.Setenv("VAULT_TOKEN", "test-token")        // Check errors if needed
	defer func() { _ = os.Unsetenv("VAULT_TOKEN") }() // Ignore error

	// Set up mock expectations for retry
	transientErr := transientNetError{errors.New("network timeout")} // Use transientNetError
	mockClient.On("Address").Return("http://vault:8200").Once()
	mockClient.On("SetToken", "test-token").Return()
	mockClient.On("Token").Return("test-token").Times(2)                                   // Called twice (initial check + retry check)
	mockAuth.On("Token").Return(mockToken).Times(2)                                        // Called twice
	mockToken.On("LookupSelfWithContext", mock.Anything).Return(nil, transientErr).Once()  // Fail first time
	mockToken.On("LookupSelfWithContext", mock.Anything).Return(&api.Secret{}, nil).Once() // Success on retry

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	err = client.Login(ctx)
	assert.NoError(t, err)
}

func TestClient_Login_K8sPermanentError(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, _, _, _, teardown := setupTest(t)
	defer teardown()

	cfg.VaultKubernetesRole = "test-role"
	_ = os.Unsetenv("VAULT_TOKEN") // Ignore error

	permErr := errors.New("invalid role") // Non-transient
	mockAuth.On("Login", ctx, mock.AnythingOfType("*kubernetes.KubernetesAuth")).Return(nil, permErr).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	err = client.Login(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentication/validation failed") // Check outer retry error
	assert.ErrorIs(t, err, permErr)
	mockAuth.AssertExpectations(t)
	mockAuth.AssertNotCalled(t, "Token") // Verify Token() was not called for K8s auth
}

func TestClient_Login_NoAuthMethod(t *testing.T) {
	ctx, cfg, mockClient, _, _, _, _, teardown := setupTest(t)
	defer teardown()

	cfg.VaultKubernetesRole = ""
	_ = os.Unsetenv("VAULT_TOKEN") // Ignore error

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	err = client.Login(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no VAULT_TOKEN environment variable set and VAULT_KUBERNETES_ROLE not configured")
}

func TestClient_GetCredentials_Success(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	// Setup mock to return a secret with all required fields
	mockClient.On("Logical").Return(mockLogical)
	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(&api.Secret{
		Data: map[string]interface{}{
			"aws_access_key":    "test-access-key",
			"aws_secret_key":    "test-secret-key",
			"pushover_api_token": "test-pushover-api",
			"pushover_user_id":   "test-pushover-user",
		},
	}, nil)

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	require.NoError(t, err)
	require.NotNil(t, creds)

	// Get underlying bytes before zeroing
	accessBytes := creds.AWSAccess.Bytes()
	secretBytes := creds.AWSSecret.Bytes()
	apiBytes := creds.PushoverAPI.Bytes()
	userBytes := creds.PushoverUser.Bytes()

	assert.Equal(t, "test-access-key", string(creds.AWSAccess))
	assert.Equal(t, "test-secret-key", string(creds.AWSSecret))
	assert.Equal(t, "test-pushover-api", string(creds.PushoverAPI))
	assert.Equal(t, "test-pushover-user", string(creds.PushoverUser))

	// Test Zero()
	creds.Zero()
	assert.Nil(t, creds.AWSAccess)
	assert.Nil(t, creds.AWSSecret)
	assert.Nil(t, creds.PushoverAPI)
	assert.Nil(t, creds.PushoverUser)

	// Check underlying slices were zeroed
	for _, b := range accessBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range secretBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range apiBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range userBytes {
		assert.Equal(t, byte(0), b)
	}

	mockLogical.AssertExpectations(t)
}

func TestClient_GetCredentials_NotFound(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	// Login
	_ = os.Setenv("VAULT_TOKEN", "test-token") // Check errors if needed
	mockClient.On("SetToken", "test-token").Return().Once()
	mockAuth.On("Token").Return(mockToken).Once()
	mockToken.On("LookupSelfWithContext", ctx).Return(&api.Secret{}, nil).Once()

	// Setup expectations for GetCredentials
	mockClient.On("Logical").Return(mockLogical).Once()

	// Mock not found
	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(nil, nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)
	err = client.Login(ctx)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "secret not found at path")
	mockLogical.AssertExpectations(t)
}

func TestClient_GetCredentials_PermanentError(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	// Login
	_ = os.Setenv("VAULT_TOKEN", "test-token") // Check errors if needed
	mockClient.On("SetToken", "test-token").Return().Once()
	mockAuth.On("Token").Return(mockToken).Once()
	mockToken.On("LookupSelfWithContext", ctx).Return(&api.Secret{}, nil).Once()

	// Setup expectations for GetCredentials
	mockClient.On("Logical").Return(mockLogical).Once()

	permErr := errors.New("permission denied")
	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(nil, permErr).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)
	err = client.Login(ctx)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "failed to read secrets") // Check outer retry error
	assert.ErrorIs(t, err, permErr)
	mockLogical.AssertExpectations(t)
}

func TestClient_GetCredentials_RetrySuccess(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	// Setup expectations for GetCredentials
	mockClient.On("Logical").Return(mockLogical)

	transientErr := transientNetError{errors.New("network timeout")}
	secretData := map[string]interface{}{
		"aws_access_key": "KEY",
		"aws_secret_key": "SECRET",
	}
	mockLogical.On("ReadWithContext", mock.Anything, cfg.VaultSecretPath).Return(nil, transientErr).Once()                  // Fail
	mockLogical.On("ReadWithContext", mock.Anything, cfg.VaultSecretPath).Return(&api.Secret{Data: secretData}, nil).Once() // Succeed

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	assert.NoError(t, err)
	require.NotNil(t, creds)

	// Get bytes before zeroing
	accessBytes := creds.AWSAccess.Bytes()
	secretBytes := creds.AWSSecret.Bytes()

	assert.Equal(t, "KEY", string(creds.AWSAccess))
	assert.Equal(t, "SECRET", string(creds.AWSSecret))

	// Test Zero()
	creds.Zero()
	assert.Nil(t, creds.AWSAccess)
	assert.Nil(t, creds.AWSSecret)

	// Check underlying slices were zeroed
	for _, b := range accessBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range secretBytes {
		assert.Equal(t, byte(0), b)
	}

	mockLogical.AssertExpectations(t)
}

func TestClient_GetCredentials_InvalidDataType(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	// Setup expectations for GetCredentials
	mockClient.On("Logical").Return(mockLogical)

	// Mock successful read with invalid data type
	secretData := map[string]interface{}{
		"aws_access_key": 12345, // Invalid type (number instead of string)
		"aws_secret_key": "valid-secret",
	}
	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(&api.Secret{Data: secretData}, nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "invalid type for 'aws_access_key'")

	mockLogical.AssertExpectations(t)
}

func TestClient_GetCredentials_MissingKeys(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	// Setup mock to return a secret with missing fields
	mockClient.On("Logical").Return(mockLogical)
	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(&api.Secret{
		Data: map[string]interface{}{
			"some_other_key": "value",
		},
	}, nil)

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	require.NoError(t, err)
	require.NotNil(t, creds)

	// All fields should be empty
	assert.Empty(t, creds.AWSAccess)
	assert.Empty(t, creds.AWSSecret)
	assert.Empty(t, creds.PushoverAPI)
	assert.Empty(t, creds.PushoverUser)

	mockLogical.AssertExpectations(t)
}

func TestClient_GetCredentials_MissingPushoverKeysWithPushoverEnabled(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	// Enable Pushover
	cfg.PushoverEnable = true
	defer func() { cfg.PushoverEnable = false }() // Reset config

	// Setup expectations for GetCredentials
	mockClient.On("Logical").Return(mockLogical)

	// Mock successful read with missing pushover keys
	secretData := map[string]interface{}{
		"aws_access_key": "ACCESSKEY",
		"aws_secret_key": "SECRETKEY",
	}
	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(&api.Secret{Data: secretData}, nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	// Execute and verify - should succeed but log warnings (which we can't easily check)
	creds, err := client.GetCredentials(ctx)
	assert.NoError(t, err) // Expect no error, just warnings
	require.NotNil(t, creds)

	// Get bytes before zeroing
	accessBytes := creds.AWSAccess.Bytes()
	secretBytes := creds.AWSSecret.Bytes()

	assert.Equal(t, "ACCESSKEY", string(creds.AWSAccess))
	assert.Equal(t, "SECRETKEY", string(creds.AWSSecret))
	assert.Nil(t, creds.PushoverAPI)
	assert.Nil(t, creds.PushoverUser)

	// Test Zero()
	creds.Zero()
	assert.Nil(t, creds.AWSAccess)
	assert.Nil(t, creds.AWSSecret)

	// Check underlying slices were zeroed
	for _, b := range accessBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range secretBytes {
		assert.Equal(t, byte(0), b)
	}

	mockLogical.AssertExpectations(t)
}

func TestClient_CreateSnapshot_Success(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	// Login
	_ = os.Setenv("VAULT_TOKEN", "test-token") // Check errors if needed
	mockClient.On("SetToken", "test-token").Return().Once()
	mockAuth.On("Token").Return(mockToken).Once()
	mockToken.On("LookupSelfWithContext", ctx).Return(&api.Secret{}, nil).Once()

	// Setup expectations for CreateSnapshot
	mockClient.On("Sys").Return(mockSys).Once()

	// Mock snapshot
	mockSys.On("RaftSnapshotWithContext", ctx, mock.AnythingOfType("*os.File")).Return(nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)
	err = client.Login(ctx)
	require.NoError(t, err)

	cfg.SkipSnapshotVerify = true // Skip verification for this simple case
	snapshotPath, err := client.CreateSnapshot(ctx)

	assert.NoError(t, err)
	assert.Equal(t, cfg.SnapshotPath, snapshotPath)
	// Check final compressed file exists
	_, err = os.Stat(snapshotPath)
	assert.NoError(t, err, "Final snapshot file should exist")
	// Check checksum file exists
	_, err = os.Stat(snapshotPath + ".sha256")
	assert.NoError(t, err, "Checksum file should exist")

	mockSys.AssertExpectations(t)
}

func TestClient_CreateSnapshot_SuccessWithVerification(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	// Login
	_ = os.Setenv("VAULT_TOKEN", "test-token") // Check errors if needed
	mockClient.On("SetToken", "test-token").Return().Once()
	mockAuth.On("Token").Return(mockToken).Once()
	mockToken.On("LookupSelfWithContext", ctx).Return(&api.Secret{}, nil).Once()

	// Setup expectations for CreateSnapshot
	mockClient.On("Sys").Return(mockSys).Once()

	// Prepare valid snapshot data for verification
	fileContent := []byte("some raft data")
	fileSum := fmt.Sprintf("%x", sha256.Sum256(fileContent))
	files := map[string][]byte{"state/raft.db": fileContent}
	checksums := map[string]string{"state/raft.db": fileSum}
	testSnapshotData := createTestTarSnapshot(t, files, checksums)
	snapshotDataToInject = testSnapshotData // Inject for the mock

	// Mock snapshot API call
	mockSys.On("RaftSnapshotWithContext", ctx, mock.AnythingOfType("*os.File")).Return(nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)
	err = client.Login(ctx)
	require.NoError(t, err)

	cfg.SkipSnapshotVerify = false // Enable verification
	snapshotPath, err := client.CreateSnapshot(ctx)

	assert.NoError(t, err)
	assert.Equal(t, cfg.SnapshotPath, snapshotPath)
	_, err = os.Stat(snapshotPath)
	assert.NoError(t, err, "Final snapshot file should exist")
	_, err = os.Stat(snapshotPath + ".sha256")
	assert.NoError(t, err, "Checksum file should exist")
	mockSys.AssertExpectations(t)
}

func TestClient_CreateSnapshot_VerificationFail(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	// Login
	_ = os.Setenv("VAULT_TOKEN", "test-token") // Check errors if needed
	mockClient.On("SetToken", "test-token").Return().Once()
	mockAuth.On("Token").Return(mockToken).Once()
	mockToken.On("LookupSelfWithContext", ctx).Return(&api.Secret{}, nil).Once()

	// Setup expectations for CreateSnapshot
	mockClient.On("Sys").Return(mockSys).Once()

	// Prepare invalid snapshot data (checksum mismatch)
	fileContent := []byte("some raft data")
	files := map[string][]byte{"state/raft.db": fileContent}
	checksums := map[string]string{"state/raft.db": "incorrectchecksum"}
	testSnapshotData := createTestTarSnapshot(t, files, checksums)
	snapshotDataToInject = testSnapshotData // Inject for the mock

	mockSys.On("RaftSnapshotWithContext", ctx, mock.AnythingOfType("*os.File")).Return(nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)
	err = client.Login(ctx)
	require.NoError(t, err)

	cfg.SkipSnapshotVerify = false // Enable verification
	snapshotPath, err := client.CreateSnapshot(ctx)

	assert.Error(t, err)
	assert.Empty(t, snapshotPath)
	assert.Contains(t, err.Error(), "checksum mismatch for file")
	// Check temporary file was removed (best effort check)
	filesInTmp, _ := filepath.Glob(filepath.Join(filepath.Dir(cfg.SnapshotPath), "vault-snapshot-*.snap.tmp"))
	assert.Empty(t, filesInTmp, "Temporary snapshot file should be removed after verification failure")

	mockSys.AssertExpectations(t)
}

func TestClient_CreateSnapshot_ApiPermanentError(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	// Login
	_ = os.Setenv("VAULT_TOKEN", "test-token") // Check errors if needed
	mockClient.On("SetToken", "test-token").Return().Once()
	mockAuth.On("Token").Return(mockToken).Once()
	mockToken.On("LookupSelfWithContext", ctx).Return(&api.Secret{}, nil).Once()

	// Setup expectations for CreateSnapshot
	mockClient.On("Sys").Return(mockSys).Once()

	permErr := errors.New("raft subsystem error")
	mockSys.On("RaftSnapshotWithContext", ctx, mock.AnythingOfType("*os.File")).Return(permErr).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)
	err = client.Login(ctx)
	require.NoError(t, err)

	snapshotPath, err := client.CreateSnapshot(ctx)

	assert.Error(t, err)
	assert.Empty(t, snapshotPath)
	assert.Contains(t, err.Error(), "failed to get Vault raft snapshot") // Check outer retry error
	assert.ErrorIs(t, err, permErr)
	mockSys.AssertExpectations(t)
}

func TestClient_Close(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, _, teardown := setupTest(t)
	defer teardown()

	// Set up mock expectations
	mockClient.On("Address").Return("http://vault:8200").Once()
	mockClient.On("Token").Return("test-token").Once()
	mockClient.On("Auth").Return(mockAuth).Once()
	mockAuth.On("Token").Return(mockToken).Once()
	mockToken.On("RevokeSelfWithContext", mock.Anything, "test-token").Return(nil).Once()
	mockClient.On("SetToken", "").Return()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	client.Close(ctx)
}

func TestClient_Close_RevokeError(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, _, teardown := setupTest(t)
	defer teardown()

	// Set up mock expectations
	mockClient.On("Address").Return("http://vault:8200").Once()
	mockClient.On("Token").Return("test-token").Once()
	mockClient.On("Auth").Return(mockAuth).Once()
	mockAuth.On("Token").Return(mockToken).Once()
	mockToken.On("RevokeSelfWithContext", mock.Anything, "test-token").Return(errors.New("revoke error")).Once()
	mockClient.On("SetToken", "").Return()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	client.Close(ctx)
}

func TestClient_Close_NoToken(t *testing.T) {
	ctx, cfg, mockClient, _, _, _, _, teardown := setupTest(t)
	defer teardown()

	// Set up mock expectations
	mockClient.On("Address").Return("http://vault:8200").Once()
	mockClient.On("Token").Return("").Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	client.Close(ctx)
}

func TestClient_Close_NilClient(t *testing.T) {
	var client *Client // nil client
	ctx := context.Background()
	// Should not panic
	assert.NotPanics(t, func() { client.Close(ctx) })
}

// --- Helper Function Tests --- //

// Assuming verifyInternalChecksums and parseSHA256SUMS are now exported or tested via CreateSnapshot
// If direct testing is needed:
func TestVerifyInternalChecksums(t *testing.T) {
	// Success Case
	t.Run("Success", func(t *testing.T) {
		fileContent := []byte("raft data")
		fileSum := fmt.Sprintf("%x", sha256.Sum256(fileContent))
		files := map[string][]byte{"state/raft.db": fileContent}
		checksums := map[string]string{"state/raft.db": fileSum}
		testSnapshotData := createTestTarSnapshot(t, files, checksums)
		r := bytes.NewReader(testSnapshotData)

		verified, err := verifyInternalChecksums(r)
		assert.NoError(t, err)
		assert.True(t, verified)
	})

	t.Run("ChecksumMismatch", func(t *testing.T) {
		fileContent := []byte("raft data")
		files := map[string][]byte{"state/raft.db": fileContent}
		checksums := map[string]string{"state/raft.db": "badchecksum"}
		testSnapshotData := createTestTarSnapshot(t, files, checksums)
		r := bytes.NewReader(testSnapshotData)

		verified, err := verifyInternalChecksums(r)
		assert.Error(t, err)
		assert.False(t, verified)
		assert.Contains(t, err.Error(), "checksum mismatch") // Expect specific mismatch error
	})

	t.Run("MissingChecksumFile", func(t *testing.T) {
		fileContent := []byte("raft data")
		files := map[string][]byte{"state/raft.db": fileContent}
		// Pass empty checksums map to helper
		testSnapshotData := createTestTarSnapshot(t, files, map[string]string{})
		r := bytes.NewReader(testSnapshotData)

		verified, err := verifyInternalChecksums(r)
		assert.Error(t, err)
		assert.False(t, verified)
		assert.Contains(t, err.Error(), "failed to parse SHA256SUMS")
	})

	t.Run("MissingDataFile", func(t *testing.T) {
		// Empty files map, but provide checksum
		checksums := map[string]string{"state/raft.db": "doesn't matter"}
		testSnapshotData := createTestTarSnapshot(t, map[string][]byte{}, checksums)
		r := bytes.NewReader(testSnapshotData)

		verified, err := verifyInternalChecksums(r)
		assert.Error(t, err)
		assert.False(t, verified)
		assert.Contains(t, err.Error(), "listed in SHA256SUMS not found") // Expect specific not found error
	})

	t.Run("InvalidTar", func(t *testing.T) {
		invalidData := []byte("this is not a tar file")
		r := bytes.NewReader(invalidData)

		verified, err := verifyInternalChecksums(r)
		assert.Error(t, err) // Expect tar reading error
		assert.False(t, verified)
	})

	t.Run("FileCountMismatch", func(t *testing.T) {
		fileContent := []byte("raft data")
		files := map[string][]byte{"state/raft.db": fileContent}
		// Checksum list has 2 files
		checksums := map[string]string{
			"state/raft.db": fmt.Sprintf("%x", sha256.Sum256(fileContent)),
			"other/file":    "dummychecksum",
		}
		testSnapshotData := createTestTarSnapshot(t, files, checksums)
		r := bytes.NewReader(testSnapshotData)

		// Should log warning but still return true if listed files match
		verified, err := verifyInternalChecksums(r)
		assert.Error(t, err) // Expect error because other/file is not found
		assert.False(t, verified)
		assert.Contains(t, err.Error(), "listed in SHA256SUMS not found")
	})
}

func TestParseSHA256SUMS(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		content := []byte("sum1  file1\nsum2  file/path/two\nsum3  file with spaces\n")
		expected := map[string]string{
			"file1":            "sum1",
			"file/path/two":    "sum2",
			"file with spaces": "sum3",
		}
		result := parseSHA256SUMS(content)
		assert.Equal(t, expected, result)
	})

	t.Run("EmptyContent", func(t *testing.T) {
		content := []byte("")
		expected := map[string]string{}
		result := parseSHA256SUMS(content)
		assert.Equal(t, expected, result)
	})

	t.Run("MalformedLines", func(t *testing.T) {
		content := []byte("sum1  file1\njustsum\n  leading space file\nsum4 file4\n") // Invalid lines
		expected := map[string]string{
			"file1":      "sum1",
			"space file": "leading", // Note: Leading space is trimmed, fields joined
			"file4":      "sum4",    // Note: Missing double space handled by Fields
		}
		result := parseSHA256SUMS(content)
		assert.Equal(t, expected, result)
	})
}

func TestCreateChecksumFile(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFilePath := filepath.Join(tmpDir, "source.dat")
	checksumFilePath := filepath.Join(tmpDir, "source.dat.sha256")

	// Create source file
	content := []byte("test data for checksum")
	err := os.WriteFile(sourceFilePath, content, 0644)
	require.NoError(t, err)

	// Calculate expected checksum
	h := sha256.New()
	h.Write(content)
	expectedSum := fmt.Sprintf("%x", h.Sum(nil))
	expectedContent := fmt.Sprintf("%s  %s\n", expectedSum, "source.dat")

	// Run the function
	err = createChecksumFile(sourceFilePath, checksumFilePath)
	assert.NoError(t, err)

	// Verify checksum file content
	actualContent, err := os.ReadFile(checksumFilePath)
	require.NoError(t, err)
	assert.Equal(t, expectedContent, string(actualContent))

	// Verify permissions (might be tricky due to umask)
	// info, err := os.Stat(checksumFilePath)
	// require.NoError(t, err)
	// assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "Checksum file permissions should be 0600")
}

func TestCreateChecksumFile_NonExistentSource(t *testing.T) {
	tmpDir := t.TempDir()
	sourceFilePath := filepath.Join(tmpDir, "non-existent-source.dat")
	checksumFilePath := filepath.Join(tmpDir, "non-existent-source.dat.sha256")

	// Run the function
	err := createChecksumFile(sourceFilePath, checksumFilePath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open file")
	assert.Contains(t, err.Error(), "no such file or directory")
}

func TestSecureString(t *testing.T) {
	original := []byte("sensitive")
	originalCopy := make([]byte, len(original))
	copy(originalCopy, original)

	ss := NewSecureString(original)

	// Check original was zeroed
	for i := range original {
		assert.Equal(t, byte(0), original[i], "Original byte slice should be zeroed")
	}

	// Check content
	assert.Equal(t, string(originalCopy), ss.String(), "String() should return original content")
	assert.Equal(t, originalCopy, ss.Bytes(), "Bytes() should return original content")

	// Check Zero()
	bytesBeforeZero := ss.Bytes()
	ss.Zero()
	assert.Nil(t, SecureString(ss), "SecureString should be nil after Zero()")

	// Check underlying bytes were zeroed
	for i := range bytesBeforeZero {
		assert.Equal(t, byte(0), bytesBeforeZero[i], "Underlying bytes should be zeroed after Zero()")
	}

	// Test NewSecureString with nil
	nilSS := NewSecureString(nil)
	assert.Nil(t, nilSS)
}

func TestVaultCredentials_Zero_NilReceiver(t *testing.T) {
	var creds *VaultCredentials // Declare as nil pointer
	// Should not panic
	assert.NotPanics(t, func() { creds.Zero() })
}

func TestIsTransientVaultError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "NilError",
			err:      nil,
			expected: false,
		},
		{
			name:     "ContextDeadlineExceeded",
			err:      context.DeadlineExceeded,
			expected: false,
		},
		{
			name:     "ContextCanceled",
			err:      context.Canceled,
			expected: false,
		},
		{
			name:     "NetworkTimeout",
			err:      transientNetError{errors.New("network timeout")},
			expected: true,
		},
		{
			name:     "UnexpectedEOF",
			err:      io.ErrUnexpectedEOF,
			expected: true,
		},
		{
			name:     "EOF",
			err:      io.EOF,
			expected: true,
		},
		{
			name:     "VaultServerError",
			err:      &api.ResponseError{StatusCode: 500},
			expected: true,
		},
		{
			name:     "VaultServiceUnavailable",
			err:      &api.ResponseError{StatusCode: 503},
			expected: true,
		},
		{
			name:     "VaultTooManyRequests",
			err:      &api.ResponseError{StatusCode: 429},
			expected: true,
		},
		{
			name:     "VaultNotFound",
			err:      &api.ResponseError{StatusCode: 404},
			expected: false,
		},
		{
			name:     "OtherError",
			err:      errors.New("some other error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTransientVaultError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewClient_InvalidConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		apiClient   VaultAPIClient
		expectError bool
	}{
		{
			name:        "NilConfig",
			config:      nil,
			apiClient:   &MockVaultAPIClient{},
			expectError: true,
		},
		{
			name:        "NilAPIClient",
			config:      &config.Config{},
			apiClient:   nil,
			expectError: true,
		},
		{
			name: "EmptyVaultAddr",
			config: &config.Config{
				VaultAddr: "",
			},
			apiClient:   &MockVaultAPIClient{},
			expectError: true,
		},
		{
			name: "EmptySecretPath",
			config: &config.Config{
				VaultAddr: "http://localhost:8200",
			},
			apiClient:   &MockVaultAPIClient{},
			expectError: true,
		},
		{
			name: "EmptySnapshotPath",
			config: &config.Config{
				VaultAddr:       "http://localhost:8200",
				VaultSecretPath: "secret/data/app/creds",
			},
			apiClient:   &MockVaultAPIClient{},
			expectError: true,
		},
		{
			name: "ValidConfig",
			config: &config.Config{
				VaultAddr:       "http://localhost:8200",
				VaultSecretPath: "secret/data/app/creds",
				SnapshotPath:    "/tmp/snapshot.gz",
			},
			apiClient:   &MockVaultAPIClient{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.apiClient != nil {
				mockClient := tt.apiClient.(*MockVaultAPIClient)
				mockClient.On("Address").Return("http://localhost:8200")
			}

			client, err := NewClient(tt.config, tt.apiClient)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestClient_CreateSnapshot_AdditionalCases(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	// Set up basic mocks shared across tests IF NOT overridden in t.Run
	mockClient.On("Sys").Return(mockSys)
	mockClient.On("Auth").Return(mockAuth)
	mockAuth.On("Token").Return(mockToken)

	t.Run("SnapshotPathError", func(t *testing.T) {
		// --- Setup for this sub-test --- //
		mockSys.ExpectedCalls = nil // Explicitly reset expectations
		// Expect API call to succeed, error happens later
		mockSys.On("RaftSnapshotWithContext", mock.Anything, mock.Anything).Return(nil).Once()

		// Create a directory where the snapshot file should be
		err := os.MkdirAll(cfg.SnapshotPath, 0755)
		require.NoError(t, err)
		defer func() { _ = os.RemoveAll(cfg.SnapshotPath) }() // Ignore error

		// Skip verification for this test to isolate the file opening error
		cfg.SkipSnapshotVerify = true
		defer func() { cfg.SkipSnapshotVerify = false }()
		// --- End Setup --- //

		client, err := NewClient(cfg, mockClient)
		require.NoError(t, err)

		_, err = client.CreateSnapshot(ctx)
		assert.Error(t, err)
		// Error occurs when trying to open finalPath for writing compression
		assert.Contains(t, err.Error(), "failed to open final snapshot file")
		assert.Contains(t, err.Error(), "is a directory") // Underlying OS error
	})

	t.Run("SnapshotWriteError", func(t *testing.T) {
		// --- Setup for this sub-test --- //
		mockSys.ExpectedCalls = nil // Explicitly reset expectations
		// *** CRITICAL: DO NOT set RaftSnapshotWithContext expectation here ***

		// Create the target directory first, then make it read-only.
		// This tests the failure of os.CreateTemp inside CreateSnapshot.
		dir := filepath.Dir(cfg.SnapshotPath)
		err := os.MkdirAll(dir, 0755) // Create with write perms first
		require.NoError(t, err)
		err = os.Chmod(dir, 0444) // Make read-only
		require.NoError(t, err)
		defer func() { _ = os.Chmod(dir, 0755) }() // Ignore error
		defer func() { _ = os.RemoveAll(dir) }()   // Ignore error

		// Skip verification (though it won't be reached)
		cfg.SkipSnapshotVerify = true
		defer func() { cfg.SkipSnapshotVerify = false }()
		// --- End Setup --- //

		client, err := NewClient(cfg, mockClient)
		require.NoError(t, err)

		_, err = client.CreateSnapshot(ctx)
		assert.Error(t, err)
		// Error should come from the os.CreateTemp call failing due to perms
		assert.Contains(t, err.Error(), "failed to create temporary snapshot file")
		assert.Contains(t, err.Error(), "permission denied") // Underlying OS error
	})

	t.Run("SnapshotAPIError", func(t *testing.T) {
		// --- Setup for this sub-test --- //
		mockSys.ExpectedCalls = nil // Explicitly reset expectations
		// Expect API call to fail
		mockSys.On("RaftSnapshotWithContext", mock.Anything, mock.Anything).Return(errors.New("API error")).Once()

		// Create a writable directory
		dir := filepath.Dir(cfg.SnapshotPath)
		err := os.MkdirAll(dir, 0755)
		require.NoError(t, err)
		defer func() { _ = os.RemoveAll(dir) }() // Ignore error

		// Skip verification (won't be reached)
		cfg.SkipSnapshotVerify = true
		defer func() { cfg.SkipSnapshotVerify = false }()
		// --- End Setup --- //

		client, err := NewClient(cfg, mockClient)
		require.NoError(t, err)

		_, err = client.CreateSnapshot(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "API error") // The error from the retry loop
	})

	t.Run("ChecksumFileError", func(t *testing.T) {
		// --- Setup for this sub-test --- //
		mockSys.ExpectedCalls = nil // Explicitly reset expectations
		// Expect successful snapshot creation API call
		mockSys.On("RaftSnapshotWithContext", mock.Anything, mock.Anything).Return(nil).Once()

		// Create a writable directory for snapshot
		dir := filepath.Dir(cfg.SnapshotPath)
		err := os.MkdirAll(dir, 0755)
		require.NoError(t, err)
		defer func() { _ = os.RemoveAll(dir) }() // Ignore error // Keep this one, RemoveAll is less likely to fail here

		// Create valid snapshot data
		files := map[string][]byte{
			"test.txt": []byte("test data"),
		}
		checksums := map[string]string{
			"test.txt": fmt.Sprintf("%x", sha256.Sum256([]byte("test data"))),
		}
		snapshotDataToInject = createTestTarSnapshot(t, files, checksums)

		// Create the directory where the checksum file will be attempted.
		checksumDir := filepath.Dir(cfg.SnapshotPath + ".sha256")
		err = os.MkdirAll(checksumDir, 0755)
		require.NoError(t, err)
		defer func() { _ = os.RemoveAll(checksumDir) }() // Ignore error

		// *** Force OverwriteFile failure by creating a DIRECTORY at the checksum file path ***
		checksumFilePath := cfg.SnapshotPath + ".sha256"
		err = os.Mkdir(checksumFilePath, 0755)
		require.NoError(t, err)
		// No need for defer remove on checksumFilePath, as RemoveAll(checksumDir) handles it.

		// Enable verification (though it might not matter here)
		cfg.SkipSnapshotVerify = false
		defer func() { cfg.SkipSnapshotVerify = false }()
		// --- End Setup --- //

		client, err := NewClient(cfg, mockClient)
		require.NoError(t, err)

		_, err = client.CreateSnapshot(ctx)
		assert.Error(t, err) // Check an error occurred
		require.NotNil(t, err)
		// Error occurs when trying to write the checksum file via util.OverwriteFile
		assert.Contains(t, err.Error(), "failed to write checksum file")
		// Check the underlying OS error (should be 'is a directory')
		assert.Contains(t, err.Error(), "is a directory")
	})

	t.Run("VerificationDisabled", func(t *testing.T) {
		// --- Setup for this sub-test --- //
		mockSys.ExpectedCalls = nil // Explicitly reset expectations
		// Expect successful snapshot creation
		mockSys.On("RaftSnapshotWithContext", mock.Anything, mock.Anything).Return(nil).Once()

		// Create a writable directory
		dir := filepath.Dir(cfg.SnapshotPath)
		err := os.MkdirAll(dir, 0755)
		require.NoError(t, err)
		defer func() { _ = os.RemoveAll(dir) }() // Ignore error

		// Create valid snapshot data
		files := map[string][]byte{
			"test.txt": []byte("test data"),
		}
		checksums := map[string]string{
			"test.txt": fmt.Sprintf("%x", sha256.Sum256([]byte("test data"))),
		}
		snapshotDataToInject = createTestTarSnapshot(t, files, checksums)

		// Enable skip verification
		cfg.SkipSnapshotVerify = true
		defer func() { cfg.SkipSnapshotVerify = false }()
		// --- End Setup --- //

		client, err := NewClient(cfg, mockClient)
		require.NoError(t, err)

		_, err = client.CreateSnapshot(ctx)
		assert.NoError(t, err)
	})
}

// TestClient_GetCredentials_KVv1Success tests successful credential retrieval from KV v1 secrets
func TestClient_GetCredentials_KVv1Success(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	// Setup mock expectations
	mockClient.On("Logical").Return(mockLogical)

	// Create a KV v1 secret response
	secret := &api.Secret{
		Data: map[string]interface{}{
			"aws_access_key": "test-access-key",
			"aws_secret_key": "test-secret-key",
			"pushover_api_token": "test-pushover-api",
			"pushover_user_id": "test-pushover-user",
		},
	}

	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(secret, nil)

	// Create client and get credentials
	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)
	require.NotNil(t, client)

	creds, err := client.GetCredentials(ctx)
	require.NoError(t, err)
	require.NotNil(t, creds)

	// Get bytes before zeroing
	accessBytes := creds.AWSAccess.Bytes()
	secretBytes := creds.AWSSecret.Bytes()
	apiBytes := creds.PushoverAPI.Bytes()
	userBytes := creds.PushoverUser.Bytes()

	// Verify credentials
	assert.Equal(t, "test-access-key", string(creds.AWSAccess))
	assert.Equal(t, "test-secret-key", string(creds.AWSSecret))
	assert.Equal(t, "test-pushover-api", string(creds.PushoverAPI))
	assert.Equal(t, "test-pushover-user", string(creds.PushoverUser))

	// Test Zero()
	creds.Zero()
	assert.Nil(t, creds.AWSAccess)
	assert.Nil(t, creds.AWSSecret)
	assert.Nil(t, creds.PushoverAPI)
	assert.Nil(t, creds.PushoverUser)

	// Check underlying slices were zeroed
	for _, b := range accessBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range secretBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range apiBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range userBytes {
		assert.Equal(t, byte(0), b)
	}

	mockLogical.AssertExpectations(t)
}

// TestClient_GetCredentials_KVv2Success tests successful credential retrieval from KV v2 secrets
func TestClient_GetCredentials_KVv2Success(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	// Setup mock to return a KV v2 secret with all required fields
	mockClient.On("Logical").Return(mockLogical)
	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(&api.Secret{
		Data: map[string]interface{}{
			"data": map[string]interface{}{
				"aws_access_key":    "test-access-key",
				"aws_secret_key":    "test-secret-key",
				"pushover_api_token": "test-pushover-api",
				"pushover_user_id":   "test-pushover-user",
			},
		},
	}, nil)

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	require.NoError(t, err)
	require.NotNil(t, creds)

	// Get underlying bytes before zeroing
	accessBytes := creds.AWSAccess.Bytes()
	secretBytes := creds.AWSSecret.Bytes()
	apiBytes := creds.PushoverAPI.Bytes()
	userBytes := creds.PushoverUser.Bytes()

	assert.Equal(t, "test-access-key", string(creds.AWSAccess))
	assert.Equal(t, "test-secret-key", string(creds.AWSSecret))
	assert.Equal(t, "test-pushover-api", string(creds.PushoverAPI))
	assert.Equal(t, "test-pushover-user", string(creds.PushoverUser))

	// Test Zero()
	creds.Zero()
	assert.Nil(t, creds.AWSAccess)
	assert.Nil(t, creds.AWSSecret)
	assert.Nil(t, creds.PushoverAPI)
	assert.Nil(t, creds.PushoverUser)

	// Check underlying slices were zeroed
	for _, b := range accessBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range secretBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range apiBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range userBytes {
		assert.Equal(t, byte(0), b)
	}

	mockLogical.AssertExpectations(t)
}

// TestClient_GetCredentials_KVv2InvalidData tests handling of invalid KV v2 data structure
func TestClient_GetCredentials_KVv2InvalidData(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	// Setup mock expectations
	mockClient.On("Logical").Return(mockLogical)

	// Create an invalid KV v2 secret response (data is not a map)
	secret := &api.Secret{
		Data: map[string]interface{}{
			"data": 123, // Invalid type for data field
		},
	}

	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(secret, nil)

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)
	require.NotNil(t, client)

	creds, err := client.GetCredentials(ctx)
	require.Error(t, err)
	require.Nil(t, creds)
	assert.Contains(t, err.Error(), "invalid data structure in KV v2 secret")

	mockLogical.AssertExpectations(t)
}

// TestClient_GetCredentials_KVv2EmptyData tests handling of empty data in KV v2 secret
func TestClient_GetCredentials_KVv2EmptyData(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	mockClient.On("Logical").Return(mockLogical)
	mockClient.On("Token").Return("test-token")

	// Create a KV v2 secret response with empty data
	secret := &api.Secret{
		Data: map[string]interface{}{
			"data": map[string]interface{}{},
		},
	}

	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(secret, nil)

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	require.NoError(t, err)
	require.NotNil(t, creds)
	assert.Nil(t, creds.AWSAccess)
	assert.Nil(t, creds.AWSSecret)
	assert.Nil(t, creds.PushoverAPI)
	assert.Nil(t, creds.PushoverUser)
}

// TestClient_GetCredentials_KVv2NilData tests handling of nil data in KV v2 secret
func TestClient_GetCredentials_KVv2NilData(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	mockClient.On("Logical").Return(mockLogical)
	mockClient.On("Token").Return("test-token")

	// Create a KV v2 secret response with nil data
	secret := &api.Secret{
		Data: map[string]interface{}{
			"data": nil,
		},
	}

	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(secret, nil)

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "invalid data structure in KV v2 secret")

	mockLogical.AssertExpectations(t)
}

// TestClient_GetCredentials_RetryTransientError tests retry behavior on transient errors
func TestClient_GetCredentials_RetryTransientError(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	mockClient.On("Logical").Return(mockLogical)

	// Create a successful KV v2 response for the second attempt
	successSecret := &api.Secret{
		Data: map[string]interface{}{ // KV v1 style for simplicity in this retry test
			"aws_access_key": "test-access-key",
			"aws_secret_key": "test-secret-key",
		},
	}

	// First call fails with transient error, second succeeds
	transientErr := transientNetError{errors.New("network timeout")}
	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(nil, transientErr).Once()
	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(successSecret, nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	require.NoError(t, err)
	require.NotNil(t, creds)

	// Get bytes before zeroing
	accessBytes := creds.AWSAccess.Bytes()
	secretBytes := creds.AWSSecret.Bytes()

	assert.Equal(t, "test-access-key", string(creds.AWSAccess))
	assert.Equal(t, "test-secret-key", string(creds.AWSSecret))

	// Test Zero()
	creds.Zero()
	assert.Nil(t, creds.AWSAccess)
	assert.Nil(t, creds.AWSSecret)

	// Check underlying slices were zeroed
	for _, b := range accessBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range secretBytes {
		assert.Equal(t, byte(0), b)
	}

	mockLogical.AssertExpectations(t)
}

// TestClient_CreateSnapshot_CompressError tests handling of compression errors
func TestClient_CreateSnapshot_CompressError(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	mockClient.On("Sys").Return(mockSys)
	mockAuth.On("Token").Return(mockToken)

	// Create valid snapshot data that will be used for compression
	files := map[string][]byte{
		"state/raft.db": []byte("test data"),
	}
	checksums := map[string]string{
		"state/raft.db": fmt.Sprintf("%x", sha256.Sum256([]byte("test data"))),
	}
	snapshotDataToInject = createTestTarSnapshot(t, files, checksums)

	mockSys.On("RaftSnapshotWithContext", mock.Anything, mock.Anything).Return(nil).Once()

	// Create the snapshot directory with write permissions
	dir := filepath.Dir(cfg.SnapshotPath)
	err := os.MkdirAll(dir, 0755)
	require.NoError(t, err)
	defer func() {
		_ = os.Chmod(dir, 0755)
		_ = os.RemoveAll(dir)
	}()

	// Create a file at the snapshot path to cause the compression to fail
	err = os.MkdirAll(cfg.SnapshotPath, 0755) // Create a directory instead of a file
	require.NoError(t, err)

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	_, err = client.CreateSnapshot(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open final snapshot file")
}

// TestClient_GetCredentials_NilSecret tests handling of nil secret response
func TestClient_GetCredentials_NilSecret(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	mockClient.On("Logical").Return(mockLogical)
	mockClient.On("Token").Return("test-token")

	// Return nil secret (not found case)
	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(nil, nil)

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "secret not found")
}

// TestClient_GetCredentials_InvalidSecretData tests handling of invalid secret data
func TestClient_GetCredentials_InvalidSecretData(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	mockClient.On("Logical").Return(mockLogical)
	mockClient.On("Token").Return("test-token")

	// Return secret with invalid data type
	secret := &api.Secret{
		Data: map[string]interface{}{
			"data": 123, // Invalid type for data field
		},
	}

	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(secret, nil)

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "invalid data structure in KV v2 secret")
}

// TestClient_GetCredentials_MixedSecretTypes tests handling of mixed secret types
// Renaming to TestClient_GetCredentials_IgnoresTopLevelIfKVv2 to be clearer
func TestClient_GetCredentials_IgnoresTopLevelIfKVv2(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	mockClient.On("Logical").Return(mockLogical)
	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(&api.Secret{
		Data: map[string]interface{}{
			"data": map[string]interface{}{
				"aws_access_key":    "kv2-access-key", // Correct value
				"aws_secret_key":    "kv2-secret-key", // Correct value
			},
			"aws_access_key": "top-level-access-key", // Should be ignored
			"aws_secret_key": "top-level-secret-key", // Should be ignored
			"pushover_api_token": "top-level-pushover-api", // Should be ignored
			"pushover_user_id":   "top-level-pushover-user", // Should be ignored
		},
	}, nil)

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	require.NoError(t, err)
	require.NotNil(t, creds)

	// Get underlying bytes before zeroing
	accessBytes := creds.AWSAccess.Bytes()
	secretBytes := creds.AWSSecret.Bytes()

	// Assert that ONLY the nested KVv2 values were used
	assert.Equal(t, "kv2-access-key", string(creds.AWSAccess))
	assert.Equal(t, "kv2-secret-key", string(creds.AWSSecret))
	assert.Nil(t, creds.PushoverAPI)  // Should be nil as it wasn't in the nested map
	assert.Nil(t, creds.PushoverUser) // Should be nil as it wasn't in the nested map

	// Test Zero()
	creds.Zero()
	assert.Nil(t, creds.AWSAccess)
	assert.Nil(t, creds.AWSSecret)
	assert.Nil(t, creds.PushoverAPI)
	assert.Nil(t, creds.PushoverUser)

	// Check underlying slices were zeroed (only check the ones that existed)
	for _, b := range accessBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range secretBytes {
		assert.Equal(t, byte(0), b)
	}

	mockLogical.AssertExpectations(t)
}

// TestClient_GetCredentials_PushoverEnabled tests handling of missing Pushover keys when enabled
func TestClient_GetCredentials_PushoverEnabled(t *testing.T) {
	ctx, cfg, mockClient, _, _, mockLogical, _, teardown := setupTest(t)
	defer teardown()

	// Enable Pushover
	cfg.PushoverEnable = true
	defer func() { cfg.PushoverEnable = false }()

	// Setup mock expectations
	mockClient.On("Logical").Return(mockLogical)

	// Create a secret with valid Pushover keys
	secret := &api.Secret{
		Data: map[string]interface{}{
			"aws_access_key": "valid-key",
			"aws_secret_key": "valid-secret",
			"pushover_api_token": "valid-api-token",
			"pushover_user_id": "valid-user-id",
		},
	}

	mockLogical.On("ReadWithContext", ctx, cfg.VaultSecretPath).Return(secret, nil)

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	creds, err := client.GetCredentials(ctx)
	require.NoError(t, err)
	require.NotNil(t, creds)

	// Get bytes before zeroing
	accessBytes := creds.AWSAccess.Bytes()
	secretBytes := creds.AWSSecret.Bytes()
	apiBytes := creds.PushoverAPI.Bytes()
	userBytes := creds.PushoverUser.Bytes()

	// Verify all fields
	assert.Equal(t, "valid-key", string(creds.AWSAccess))
	assert.Equal(t, "valid-secret", string(creds.AWSSecret))
	assert.Equal(t, "valid-api-token", string(creds.PushoverAPI))
	assert.Equal(t, "valid-user-id", string(creds.PushoverUser))

	// Test Zero()
	creds.Zero()
	assert.Nil(t, creds.AWSAccess)
	assert.Nil(t, creds.AWSSecret)
	assert.Nil(t, creds.PushoverAPI)
	assert.Nil(t, creds.PushoverUser)

	// Check underlying slices were zeroed
	for _, b := range accessBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range secretBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range apiBytes {
		assert.Equal(t, byte(0), b)
	}
	for _, b := range userBytes {
		assert.Equal(t, byte(0), b)
	}

	mockLogical.AssertExpectations(t)
}

// TestClient_CreateSnapshot_VerifyWithoutChecksum tests verification without checksum file
func TestClient_CreateSnapshot_VerifyWithoutChecksum(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	mockClient.On("Sys").Return(mockSys)
	mockAuth.On("Token").Return(mockToken)

	// Create snapshot data without checksum file
	files := map[string][]byte{
		"state/raft.db": []byte("test data"),
	}
	// Don't include checksums
	snapshotDataToInject = createTestTarSnapshot(t, files, nil)

	mockSys.On("RaftSnapshotWithContext", mock.Anything, mock.Anything).Return(nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	cfg.SkipSnapshotVerify = false // Enable verification
	_, err = client.CreateSnapshot(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse SHA256SUMS")
}

// TestClient_CreateSnapshot_InvalidSnapshotData tests handling of invalid snapshot data
func TestClient_CreateSnapshot_InvalidSnapshotData(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	mockClient.On("Sys").Return(mockSys)
	mockAuth.On("Token").Return(mockToken)

	// Create invalid snapshot data (not a tar file)
	snapshotDataToInject = []byte("invalid tar data")

	mockSys.On("RaftSnapshotWithContext", mock.Anything, mock.Anything).Return(nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	cfg.SkipSnapshotVerify = false // Enable verification
	_, err = client.CreateSnapshot(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read tar header")
}

// TestClient_CreateSnapshot_EmptySnapshot tests handling of empty snapshot
func TestClient_CreateSnapshot_EmptySnapshot(t *testing.T) {
	ctx, cfg, mockClient, _, _, _, mockSys, teardown := setupTest(t)
	defer teardown()

	// Setup mock expectations
	mockClient.On("Sys").Return(mockSys)

	// Mock empty snapshot
	mockSys.On("RaftSnapshotWithContext", ctx, mock.AnythingOfType("*os.File")).Run(func(args mock.Arguments) {
		// Do nothing - simulate empty snapshot
	}).Return(nil)

	// Create client (needed for the call)
	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	// Execute
	snapshotPath, err := client.CreateSnapshot(ctx)
	assert.Error(t, err)
	assert.Empty(t, snapshotPath)
	assert.Contains(t, err.Error(), "failed to read tar header")

	mockSys.AssertExpectations(t)
}

// TestClient_CreateSnapshot_InvalidPath tests handling of invalid snapshot paths
func TestClient_CreateSnapshot_InvalidPath(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	// Set an invalid path (directory instead of file)
	cfg.SnapshotPath = "/tmp/"

	mockClient.On("Sys").Return(mockSys)
	mockAuth.On("Token").Return(mockToken)

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	_, err = client.CreateSnapshot(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be a full file path")
}

// TestClient_CreateSnapshot_ContextTimeout tests handling of context timeout
func TestClient_CreateSnapshot_ContextTimeout(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	// Create a context with timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 1*time.Millisecond)
	defer cancel()

	mockClient.On("Sys").Return(mockSys)
	mockAuth.On("Token").Return(mockToken)

	// Mock that the API call takes longer than the timeout
	mockSys.On("RaftSnapshotWithContext", ctxWithTimeout, mock.Anything).Run(func(args mock.Arguments) {
		time.Sleep(10 * time.Millisecond) // Sleep longer than timeout
	}).Return(context.DeadlineExceeded).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	_, err = client.CreateSnapshot(ctxWithTimeout)
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestClient_CreateSnapshot_RetrySuccess tests successful retry after transient error
func TestClient_CreateSnapshot_RetrySuccess(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	mockClient.On("Sys").Return(mockSys)
	mockAuth.On("Token").Return(mockToken)

	// Create valid snapshot data
	files := map[string][]byte{
		"state/raft.db": []byte("test data"),
	}
	checksums := map[string]string{
		"state/raft.db": fmt.Sprintf("%x", sha256.Sum256([]byte("test data"))),
	}
	snapshotDataToInject = createTestTarSnapshot(t, files, checksums)

	// First call fails with transient error, second succeeds
	transientErr := transientNetError{errors.New("network timeout")}
	mockSys.On("RaftSnapshotWithContext", ctx, mock.Anything).Return(transientErr).Once()
	mockSys.On("RaftSnapshotWithContext", ctx, mock.Anything).Return(nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	cfg.SkipSnapshotVerify = true // Skip verification for this test
	snapshotPath, err := client.CreateSnapshot(ctx)
	assert.NoError(t, err)
	assert.Equal(t, cfg.SnapshotPath, snapshotPath)
}

// TestClient_CreateSnapshot_RetryExhausted tests handling of exhausted retries
func TestClient_CreateSnapshot_RetryExhausted(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	mockClient.On("Sys").Return(mockSys)
	mockAuth.On("Token").Return(mockToken)

	// Create valid snapshot data
	files := map[string][]byte{
		"state/raft.db": []byte("test data"),
	}
	checksums := map[string]string{
		"state/raft.db": fmt.Sprintf("%x", sha256.Sum256([]byte("test data"))),
	}
	snapshotDataToInject = createTestTarSnapshot(t, files, checksums)

	// All calls fail with transient error
	transientErr := transientNetError{errors.New("network timeout")}
	mockSys.On("RaftSnapshotWithContext", ctx, mock.Anything).Return(transientErr)

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	cfg.SkipSnapshotVerify = true // Skip verification for this test
	_, err = client.CreateSnapshot(ctx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, transientErr)
}

// TestClient_CreateSnapshot_VerifyChecksumMismatch tests handling of checksum mismatch during verification
func TestClient_CreateSnapshot_VerifyChecksumMismatch(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	mockClient.On("Sys").Return(mockSys)
	mockAuth.On("Token").Return(mockToken)

	// Create snapshot data with mismatched checksum
	files := map[string][]byte{
		"state/raft.db": []byte("test data"),
	}
	checksums := map[string]string{
		"state/raft.db": "incorrect_checksum",
	}
	snapshotDataToInject = createTestTarSnapshot(t, files, checksums)

	mockSys.On("RaftSnapshotWithContext", mock.Anything, mock.Anything).Return(nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	cfg.SkipSnapshotVerify = false // Enable verification
	_, err = client.CreateSnapshot(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")
}

// TestClient_CreateSnapshot_VerifyMissingFile tests handling of missing file during verification
func TestClient_CreateSnapshot_VerifyMissingFile(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	mockClient.On("Sys").Return(mockSys)
	mockAuth.On("Token").Return(mockToken)

	// Create snapshot data with checksum for non-existent file
	files := map[string][]byte{} // No files
	checksums := map[string]string{
		"state/raft.db": "some_checksum", // Checksum for non-existent file
	}
	snapshotDataToInject = createTestTarSnapshot(t, files, checksums)

	mockSys.On("RaftSnapshotWithContext", mock.Anything, mock.Anything).Return(nil).Once()

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	cfg.SkipSnapshotVerify = false // Enable verification
	_, err = client.CreateSnapshot(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "listed in SHA256SUMS not found")
}
