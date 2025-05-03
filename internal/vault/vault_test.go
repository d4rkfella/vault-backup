package vault

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
		dataToUse := snapshotDataToInject
		if dataToUse == nil {
			// Create minimal valid gzipped tar for dummy data
			var buf bytes.Buffer
			gzw := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gzw)
			// Add a dummy file to avoid tar errors on empty archives
			hdr := &tar.Header{Name: "dummy.txt", Size: 0, Mode: 0600}
			if err := tw.WriteHeader(hdr); err != nil {
				// If dummy creation fails, return error (should not happen)
				snapshotDataToInject = nil // Clear injected data
				return fmt.Errorf("failed to write dummy tar header: %w", err)
			}
			if err := tw.Close(); err != nil {
				snapshotDataToInject = nil
				return fmt.Errorf("failed to close dummy tar writer: %w", err)
			}
			if err := gzw.Close(); err != nil {
				snapshotDataToInject = nil
				return fmt.Errorf("failed to close dummy gzip writer: %w", err)
			}
			dataToUse = buf.Bytes()
		} else {
			// If data was injected (likely raw tar), gzip it before writing
			var gzippedBuf bytes.Buffer
			gzw := gzip.NewWriter(&gzippedBuf)
			if _, err := gzw.Write(dataToUse); err != nil {
				snapshotDataToInject = nil // Clear injected data on error
				return fmt.Errorf("failed to gzip injected snapshot data: %w", err)
			}
			if err := gzw.Close(); err != nil {
				snapshotDataToInject = nil // Clear injected data on error
				return fmt.Errorf("failed to close gzip writer for injected data: %w", err)
			}
			dataToUse = gzippedBuf.Bytes()
		}

		_, writeErr := w.Write(dataToUse)
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
		SnapshotPath:             tmpDir,
		LogLevel:                 "trace",
		VaultKubernetesTokenPath: dummyTokenPath,
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
	// Assert that a path was returned and it's inside the configured directory
	assert.NotEmpty(t, snapshotPath)
	assert.True(t, strings.HasPrefix(snapshotPath, cfg.SnapshotPath), "Expected snapshot path %q to be inside %q", snapshotPath, cfg.SnapshotPath)
	assert.True(t, strings.HasSuffix(snapshotPath, ".snap"))

	// Check final file exists
	_, err = os.Stat(snapshotPath)
	assert.NoError(t, err, "Final snapshot file should exist")

	mockSys.AssertExpectations(t)
}

func TestClient_CreateSnapshot_AdditionalCases(t *testing.T) {
	ctx, cfg, mockClient, mockAuth, mockToken, _, mockSys, teardown := setupTest(t)
	defer teardown()

	// Set up basic mocks shared across tests IF NOT overridden in t.Run
	mockClient.On("Sys").Return(mockSys)
	mockClient.On("Auth").Return(mockAuth)
	mockAuth.On("Token").Return(mockToken)

	t.Run("SnapshotWriteError", func(t *testing.T) {
		// --- Setup for this sub-test --- //
		mockSys.ExpectedCalls = nil // Explicitly reset expectations

		// Create the target directory first, then make it read-only
		dir := cfg.SnapshotPath
		err := os.Chmod(dir, 0444) // Make read-only
		require.NoError(t, err)
		// Use t.Cleanup for robust cleanup
		t.Cleanup(func() { _ = os.Chmod(dir, 0755) })

		client, err := NewClient(cfg, mockClient)
		require.NoError(t, err)

		_, err = client.CreateSnapshot(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create snapshot file")
		assert.Contains(t, err.Error(), "permission denied") // Underlying OS error
	})

	t.Run("SnapshotAPIError", func(t *testing.T) {
		// --- Setup for this sub-test --- //
		mockSys.ExpectedCalls = nil // Explicitly reset expectations
		// Expect API call to fail
		mockSys.On("RaftSnapshotWithContext", mock.Anything, mock.Anything).Return(errors.New("API error")).Once()

		// Ensure directory is writable
		dir := cfg.SnapshotPath
		err := os.Chmod(dir, 0755)
		require.NoError(t, err)

		client, err := NewClient(cfg, mockClient)
		require.NoError(t, err)

		_, err = client.CreateSnapshot(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create Vault snapshot") // Check outer error message
		assert.Contains(t, err.Error(), "API error") // Check inner error message
	})

	t.Run("VerificationDisabled", func(t *testing.T) {
		// --- Setup for this sub-test --- //
		mockSys.ExpectedCalls = nil // Explicitly reset expectations
		// Expect successful snapshot creation
		mockSys.On("RaftSnapshotWithContext", mock.Anything, mock.Anything).Return(nil).Once()

		// Ensure directory is writable
		dir := cfg.SnapshotPath
		err := os.Chmod(dir, 0755)
		require.NoError(t, err)

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

		client, err := NewClient(cfg, mockClient)
		require.NoError(t, err)

		snapshotPath, err := client.CreateSnapshot(ctx)
		assert.NoError(t, err)
		assert.NotEmpty(t, snapshotPath)

		// Verify the file exists
		_, err = os.Stat(snapshotPath)
		assert.NoError(t, err, "Snapshot file should exist")
	})
}

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
	// The mock now gzips the invalid data, so verifyInternalChecksums should report invalid tar header
	assert.Contains(t, err.Error(), "failed to read tar header")
}

func TestClient_CreateSnapshot_InvalidPath(t *testing.T) {
	ctx, cfg, mockClient, _, _, _, _, teardown := setupTest(t)
	defer teardown()

	// Create a temporary *file* to use as an invalid path
	tmpFile, err := os.CreateTemp(t.TempDir(), "i_am_a_file_not_a_dir")
	require.NoError(t, err)
	tmpFilePath := tmpFile.Name()
	tmpFile.Close() // Close the file handle
	t.Cleanup(func() { os.Remove(tmpFilePath) }) // Clean up the temp file

	// Set SnapshotPath to the existing file, which is invalid (must be a directory)
	cfg.SnapshotPath = tmpFilePath

	// No Sys/Auth/Token mocks needed here, as the error should occur before API calls

	client, err := NewClient(cfg, mockClient)
	require.NoError(t, err)

	// CreateSnapshot should fail early because the path is a file, not a directory
	_, err = client.CreateSnapshot(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "snapshot path")
	assert.Contains(t, err.Error(), "is not a directory") // Verify the specific error message
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

	// Login (needed because mockAuth/mockToken are used)
	_ = os.Setenv("VAULT_TOKEN", "test-token")
	defer func() { _ = os.Unsetenv("VAULT_TOKEN") }()
	mockClient.On("SetToken", "test-token").Return().Once()
	mockToken.On("LookupSelfWithContext", ctx).Return(&api.Secret{}, nil).Once()

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
	err = client.Login(ctx) // Perform login
	require.NoError(t, err)

	cfg.SkipSnapshotVerify = true // Skip verification for this test
	snapshotPath, err := client.CreateSnapshot(ctx)
	assert.NoError(t, err)

	// Assert that a path was returned and it's inside the configured directory
	assert.NotEmpty(t, snapshotPath)
	assert.True(t, strings.HasPrefix(snapshotPath, cfg.SnapshotPath), "Expected snapshot path %q to be inside %q", snapshotPath, cfg.SnapshotPath)
	assert.True(t, strings.HasSuffix(snapshotPath, ".snap"))

	// Optional: Check file existence if needed
	_, err = os.Stat(snapshotPath)
	assert.NoError(t, err, "Final snapshot file should exist after retry")
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
	assert.Contains(t, err.Error(), "listed in SHA256SUMS not found") // Should correctly fail verification now
}
