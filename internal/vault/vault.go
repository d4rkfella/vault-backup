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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/kubernetes"
	"github.com/rs/zerolog/log"

	// Import the config package we created
	// The module path needs to be correctly determined. Assuming 'vault-backup' is the module name.
	// You might need to adjust this based on your go.mod file.
	"github.com/d4rkfella/vault-backup/internal/config"
	"github.com/d4rkfella/vault-backup/internal/retry"
	"github.com/d4rkfella/vault-backup/internal/util"
)

// --- Retry Config --- // ADDED SECTION
const (
	defaultMaxAttempts  = 5
	defaultInitialDelay = 500 * time.Millisecond
	defaultMaxDelay     = 15 * time.Second
)

var defaultRetryConfig = retry.Config{
	MaxAttempts:  defaultMaxAttempts,
	InitialDelay: defaultInitialDelay,
	MaxDelay:     defaultMaxDelay,
}

// --- End Retry Config --- //

// SecureString is a byte slice wrapper designed to hold sensitive data (like passwords or API keys).
// It attempts to securely zero out the underlying memory when no longer needed via the Zero() method,
// although Go's memory management makes guarantees difficult.
// Use String() and Bytes() methods with caution, only when necessary to interact with external libraries.
type SecureString []byte

// NewSecureString creates a new SecureString by copying the input byte slice.
// Crucially, it also attempts to zero out the original input slice `b` after copying.
func NewSecureString(b []byte) SecureString {
	if b == nil {
		return nil
	}
	ss := make(SecureString, len(b))
	copy(ss, b)
	zeroBytes(b) // Zero the original slice
	return ss
}

// String returns the string representation of the SecureString's content.
// WARNING: Avoid using this where possible; prefer methods that operate directly on SecureString
// or pass the byte slice representation carefully.
func (ss SecureString) String() string {
	return string(ss)
}

// Bytes returns the underlying byte slice of the SecureString.
// WARNING: Use with caution. The returned slice shares the same backing array.
// Modifications to the returned slice will affect the SecureString, and vice versa.
// Prefer methods operating directly on SecureString where possible.
func (ss SecureString) Bytes() []byte {
	return []byte(ss)
}

// Zero attempts to securely clear the memory occupied by the SecureString's byte slice.
// It iterates through the slice setting each byte to zero and then nils the slice header.
// Includes runtime.KeepAlive as a best effort against compiler optimization.
func (ss *SecureString) Zero() {
	if ss == nil || *ss == nil {
		return
	}
	zeroBytes(*ss)
	*ss = nil
}

// zeroBytes securely zeros out a byte slice.
// Used internally by SecureString methods.
func zeroBytes(b []byte) {
	// Basic zeroing
	for i := range b {
		b[i] = 0
	}
	// Attempt to prevent compiler optimization (best effort)
	runtime.KeepAlive(b)
}

// VaultCredentials holds sensitive credentials (AWS keys, Pushover keys) fetched from Vault.
// It uses SecureString for the credential fields.
type VaultCredentials struct {
	AWSAccess    SecureString
	AWSSecret    SecureString
	PushoverAPI  SecureString
	PushoverUser SecureString
}

// Zero securely clears all SecureString fields within the VaultCredentials struct.
func (vc *VaultCredentials) Zero() {
	if vc == nil {
		return
	}
	vc.AWSAccess.Zero()
	vc.AWSSecret.Zero()
	vc.PushoverAPI.Zero()
	vc.PushoverUser.Zero()
}

// --- Retry Logic Helper ---

// isTransientVaultError checks if the error from a Vault API call suggests a retry might succeed.
// This includes network errors, timeouts, and specific HTTP status codes (e.g., 5xx, 429).
// NOTE: This function is now used as the IsRetryableFunc for the retry package.
func isTransientVaultError(err error) bool {
	if err == nil {
		return false
	}

	// Check for context cancellation/timeout first
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false // Don't retry if context is done
	}

	// Check for common network errors
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true // Network timeout
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true // Connection closed prematurely
	}

	// Check Vault API specific errors (if client library surfaces them)
	// Example: Check for 5xx errors if the error includes HTTP response info
	// This part depends heavily on how hashicorp/vault/api wraps errors.
	// Let's assume for now it might wrap an *url.Error or similar for HTTP issues.
	var respErr *api.ResponseError
	if errors.As(err, &respErr) {
		if respErr.StatusCode >= 500 && respErr.StatusCode < 600 {
			// Vault server errors (500, 502, 503, 504) are often transient
			return true
		}
		// Sealed (503), standby (473?), performance standby (472?) might be retryable
		if respErr.StatusCode == http.StatusServiceUnavailable ||
			respErr.StatusCode == http.StatusTooManyRequests { // Example non-standard codes
			return true
		}
	}

	// Add more checks based on observed transient errors

	log.Debug().Err(err).Msg("Encountered non-transient Vault error")
	return false
}

// --- Vault API Interface for Mocking ---

// VaultAPIClient defines the interface for Vault API interactions needed by this package.
// This allows mocking the Vault client for testing.
type VaultAPIClient interface {
	Auth() AuthAPI
	Logical() LogicalAPI
	Sys() SysAPI
	SetToken(v string)
	Token() string
	Address() string // Needed for logging/info potentially
}

// AuthAPI defines the authentication-related methods used.
type AuthAPI interface {
	Login(ctx context.Context, authMethod api.AuthMethod) (*api.Secret, error)
	Token() TokenAPI
}

// TokenAPI defines the token-related methods used.
type TokenAPI interface {
	LookupSelfWithContext(ctx context.Context) (*api.Secret, error)
	RevokeSelfWithContext(ctx context.Context, token string) error
}

// LogicalAPI defines the logical backend methods used.
type LogicalAPI interface {
	ReadWithContext(ctx context.Context, path string) (*api.Secret, error)
}

// SysAPI defines the system backend methods used.
type SysAPI interface {
	RaftSnapshotWithContext(ctx context.Context, w io.Writer) error
}

// --- Client Struct ---

// Client holds the Vault configuration and the authenticated client.
// Uses VaultAPIClient interface for testability.
type Client struct {
	config *config.Config
	client VaultAPIClient
	// No logger here, use global log or pass explicitly to methods if needed
}

// vaultAPIClientAdapter adapts the HashiCorp Vault API client to our VaultAPIClient interface
type vaultAPIClientAdapter struct {
	client *api.Client
}

func (a *vaultAPIClientAdapter) Auth() AuthAPI {
	return &authAPIAdapter{a.client.Auth()}
}

func (a *vaultAPIClientAdapter) Logical() LogicalAPI {
	return &logicalAPIAdapter{a.client.Logical()}
}

func (a *vaultAPIClientAdapter) Sys() SysAPI {
	return &sysAPIAdapter{a.client.Sys()}
}

func (a *vaultAPIClientAdapter) SetToken(v string) {
	a.client.SetToken(v)
}

func (a *vaultAPIClientAdapter) Token() string {
	return a.client.Token()
}

func (a *vaultAPIClientAdapter) Address() string {
	return a.client.Address()
}

// authAPIAdapter adapts the HashiCorp Vault Auth API to our AuthAPI interface
type authAPIAdapter struct {
	auth *api.Auth
}

func (a *authAPIAdapter) Login(ctx context.Context, authMethod api.AuthMethod) (*api.Secret, error) {
	return a.auth.Login(ctx, authMethod)
}

func (a *authAPIAdapter) Token() TokenAPI {
	return &tokenAPIAdapter{token: a.auth}
}

// tokenAPIAdapter adapts the HashiCorp Vault Token API to our TokenAPI interface
type tokenAPIAdapter struct {
	token *api.Auth
}

func (a *tokenAPIAdapter) LookupSelfWithContext(ctx context.Context) (*api.Secret, error) {
	return a.token.Token().LookupSelfWithContext(ctx)
}

func (a *tokenAPIAdapter) RevokeSelfWithContext(ctx context.Context, token string) error {
	return a.token.Token().RevokeSelfWithContext(ctx, token)
}

// logicalAPIAdapter adapts the HashiCorp Vault Logical API to our LogicalAPI interface
type logicalAPIAdapter struct {
	logical *api.Logical
}

func (a *logicalAPIAdapter) ReadWithContext(ctx context.Context, path string) (*api.Secret, error) {
	return a.logical.ReadWithContext(ctx, path)
}

// sysAPIAdapter adapts the HashiCorp Vault Sys API to our SysAPI interface
type sysAPIAdapter struct {
	sys *api.Sys
}

func (a *sysAPIAdapter) RaftSnapshotWithContext(ctx context.Context, w io.Writer) error {
	return a.sys.RaftSnapshotWithContext(ctx, w)
}

// NewClient creates a new Vault client wrapper. It does NOT authenticate yet.
// Authentication happens in Login(). Accepts an optional apiClient for testing.
// If apiClient is nil, a real Vault API client will be created.
func NewClient(cfg *config.Config, apiClient VaultAPIClient) (*Client, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}

	if cfg.VaultAddr == "" {
		return nil, errors.New("vault address cannot be empty")
	}

	if cfg.VaultSecretPath == "" {
		return nil, errors.New("vault secret path cannot be empty")
	}

	if cfg.SnapshotPath == "" {
		return nil, errors.New("snapshot path cannot be empty")
	}

	// If no API client is provided, create a real one
	if apiClient == nil {
		client, err := api.NewClient(&api.Config{
			Address: cfg.VaultAddr,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create Vault API client: %w", err)
		}
		apiClient = &vaultAPIClientAdapter{client: client}
	}

	return &Client{
		config: cfg,
		client: apiClient,
	}, nil
}

// Login authenticates the client using the configured method (Kubernetes or Token).
// Includes custom retry logic for authentication and token verification steps.
func (c *Client) Login(ctx context.Context) error {
	if c == nil || c.client == nil {
		return errors.New("client is not initialized")
	}
	cfg := c.config // Use the stored config

	// --- Retry Block using custom retry --- //
	loginOperation := func(opCtx context.Context) error { // Operation now takes context
		var innerErr error
		var authMethod api.AuthMethod // Interface for different auth methods

		if cfg.VaultKubernetesRole != "" {
			log.Info().Str("component", "vault").Str("role", cfg.VaultKubernetesRole).Msg("Attempting Vault Kubernetes auth")
			// Use configured token path

			// Determine the auth method based on token path presence
			if cfg.VaultKubernetesTokenPath != "" {
				log.Debug().Str("path", cfg.VaultKubernetesTokenPath).Msg("Using custom Kubernetes token path")
				k8sOption := kubernetes.WithServiceAccountTokenPath(cfg.VaultKubernetesTokenPath)

				// TODO: Add VaultKubernetesMountPath handling if needed
				// if cfg.VaultKubernetesMountPath != "" { ... }

				// Call NewKubernetesAuth with the single option
				authMethod, innerErr = kubernetes.NewKubernetesAuth(cfg.VaultKubernetesRole, k8sOption)
			} else {
				log.Debug().Msg("Using default Kubernetes token path and no extra options")
				// Call NewKubernetesAuth with just the role (no options)
				authMethod, innerErr = kubernetes.NewKubernetesAuth(cfg.VaultKubernetesRole)
			}

			// Check error from NewKubernetesAuth immediately
			if innerErr != nil {
				// Wrap error for clarity, still permanent (no retry needed for this)
				innerErr = fmt.Errorf("failed to create k8s auth method: %w", innerErr)
				// Return non-retryable error immediately
				return innerErr // Note: isTransientVaultError will return false
			}

			var loginSecret *api.Secret
			loginSecret, innerErr = c.client.Auth().Login(opCtx, authMethod) // Use opCtx and interface method
			if innerErr == nil && loginSecret == nil {
				innerErr = errors.New("kubernetes auth login returned nil secret and nil error") // Should not happen
			}
			if innerErr == nil {
				log.Info().Str("component", "vault").Msg("Kubernetes auth successful")
				// Token is implicitly set by the Login call for the underlying client
			}
		} else if token := os.Getenv("VAULT_TOKEN"); token != "" {
			log.Info().Str("component", "vault").Msg("Using VAULT_TOKEN for authentication")
			c.client.SetToken(token) // Use interface method
			// Verify token
			_, innerErr = c.client.Auth().Token().LookupSelfWithContext(opCtx) // Use opCtx and interface method
		} else {
			innerErr = errors.New("no VAULT_TOKEN environment variable set and VAULT_KUBERNETES_ROLE not configured")
			// Config error, don't retry (isTransientVaultError will return false)
			return innerErr
		}

		// Return the result of the attempt (nil on success, error on failure)
		return innerErr // This error will be checked by isTransientVaultError
	}

	// Execute the operation with retry
	err := retry.ExecuteWithRetry(ctx, defaultRetryConfig, loginOperation, isTransientVaultError, "VaultLogin")
	if err != nil {
		log.Error().Err(err).Msg("Vault auth/token validation failed after retries")
		// Wrap the final error
		return fmt.Errorf("vault authentication/validation failed: %w", err)
	}

	// --- End Retry Block --- //

	log.Info().Str("component", "vault").Msg("Vault client authenticated")
	return nil
}

// GetCredentials fetches secrets (AWS keys, Pushover keys) from the specified KV secret path in Vault.
// It includes custom retry logic for the Vault read operation.
func (c *Client) GetCredentials(ctx context.Context) (*VaultCredentials, error) {
	if c == nil || c.client == nil {
		return nil, errors.New("client is not initialized or authenticated")
	}
	// Ensure secret path is configured
	secretPath := c.config.VaultSecretPath
	if secretPath == "" {
		// Config error, no retry needed
		return nil, fmt.Errorf("VAULT_SECRET_PATH is not configured")
	}

	log.Info().Str("component", "vault").Str("path", util.SanitizePath(secretPath)).Msg("Fetching secrets")

	var secret *api.Secret
	var readErr error // Variable to store the error from the operation

	// --- Retry Block using custom retry --- //
	readOperation := func(opCtx context.Context) error {
		var innerErr error
		secret, innerErr = c.client.Logical().ReadWithContext(opCtx, secretPath) // Use opCtx and interface method

		if innerErr != nil {
			// Return the error to be checked by isTransientVaultError
			return innerErr
		}
		if secret == nil {
			// Treat "not found" as a permanent error - isTransientVaultError should return false
			innerErr = fmt.Errorf("secret not found at path: %s", util.SanitizePath(secretPath))
			// Check if the underlying error indicates a 404, which is common for "not found"
			var respErr *api.ResponseError
			if errors.As(innerErr, &respErr) && respErr.StatusCode == http.StatusNotFound {
				log.Error().Str("path", util.SanitizePath(secretPath)).Int("status_code", respErr.StatusCode).Msg("Secret not found at path")
			}
			return innerErr
		}
		// Potential check for warnings?
		if len(secret.Warnings) > 0 {
			log.Warn().Strs("warnings", secret.Warnings).Str("path", util.SanitizePath(secretPath)).Msg("Received warnings while reading secret")
		}
		readErr = nil // Explicitly nil error on success
		return nil    // Success
	}

	// Execute the operation with retry
	// Store the final error in readErr
	readErr = retry.ExecuteWithRetry(ctx, defaultRetryConfig, readOperation, isTransientVaultError, "VaultReadSecret")

	// Check the final error after retries
	if readErr != nil {
		log.Error().Err(readErr).Str("path", util.SanitizePath(secretPath)).Msg("Vault read failed after retries")
		return nil, fmt.Errorf("failed to read secrets from Vault path %s: %w", util.SanitizePath(secretPath), readErr)
	}
	// --- End Retry Block --- //

	// If we reach here, readOperation succeeded within the retry loop, and 'secret' is populated.

	if secret.Data == nil {
		// This might occur if the secret exists but has no data fields
		log.Warn().Str("path", util.SanitizePath(secretPath)).Msg("No data found in secret")
		// Return empty creds instead of error? Or error? Let's return error for now.
		return nil, fmt.Errorf("no data found in secret at path: %s", util.SanitizePath(secretPath))
	}

	// Handle KV v2 secrets - check for data field
	var secretData map[string]interface{}
	if data, ok := secret.Data["data"]; ok {
		// This is a KV v2 secret
		if dataMap, ok := data.(map[string]interface{}); ok {
			secretData = dataMap
		} else {
			return nil, fmt.Errorf("invalid data structure in KV v2 secret at path: %s", util.SanitizePath(secretPath))
		}
	} else {
		// This is a KV v1 secret
		secretData = secret.Data
	}

	// Extract data into SecureString fields
	creds := &VaultCredentials{}
	var ok bool
	var awsAccess, awsSecret, pushAPI, pushUser string

	// Helper function to extract and zero string
	extract := func(key string) (string, bool) {
		val, exists := secretData[key]
		if !exists {
			return "", false
		}
		strVal, ok := val.(string)
		if !ok {
			log.Error().Str("key", key).Str("path", util.SanitizePath(secretPath)).Msg("Invalid type for key in secret")
			// Mark as not ok, but don't return error immediately, allows processing other keys
			return "", false
		}
		return strVal, true
	}

	var extractErr error // Keep track of extraction errors

	if awsAccess, ok = extract("aws_access_key_id"); ok {
		creds.AWSAccess = NewSecureString([]byte(awsAccess))
		defer zeroBytes([]byte(awsAccess)) // Zero intermediate string bytes
	} else if _, exists := secretData["aws_access_key_id"]; exists && !ok { // Only error if key exists but type is wrong
		extractErr = errors.Join(extractErr, fmt.Errorf("invalid type for 'aws_access_key_id' in secret %s", util.SanitizePath(secretPath)))
	} else { // Key doesn't exist
		log.Warn().Str("path", util.SanitizePath(secretPath)).Msg("'aws_access_key_id' not found in secret")
	}

	if awsSecret, ok = extract("aws_secret_access_key"); ok {
		creds.AWSSecret = NewSecureString([]byte(awsSecret))
		defer zeroBytes([]byte(awsSecret))
	} else if _, exists := secretData["aws_secret_access_key"]; exists && !ok {
		extractErr = errors.Join(extractErr, fmt.Errorf("invalid type for 'aws_secret_access_key' in secret %s", util.SanitizePath(secretPath)))
	} else {
		log.Warn().Str("path", util.SanitizePath(secretPath)).Msg("'aws_secret_access_key' not found in secret")
	}

	if pushAPI, ok = extract("pushover_api_token"); ok {
		creds.PushoverAPI = NewSecureString([]byte(pushAPI))
		defer zeroBytes([]byte(pushAPI))
	} else if _, exists := secretData["pushover_api_token"]; exists && !ok {
		extractErr = errors.Join(extractErr, fmt.Errorf("invalid type for 'pushover_api_token' in secret %s", util.SanitizePath(secretPath)))
	} else {
		if c.config.PushoverEnable {
			log.Warn().Str("path", util.SanitizePath(secretPath)).Msg("'pushover_api_token' not found in secret, but Pushover is enabled")
		}
	}

	if pushUser, ok = extract("pushover_user_key"); ok {
		creds.PushoverUser = NewSecureString([]byte(pushUser))
		defer zeroBytes([]byte(pushUser))
	} else if _, exists := secretData["pushover_user_key"]; exists && !ok {
		extractErr = errors.Join(extractErr, fmt.Errorf("invalid type for 'pushover_user_key' in secret %s", util.SanitizePath(secretPath)))
	} else {
		if c.config.PushoverEnable {
			log.Warn().Str("path", util.SanitizePath(secretPath)).Msg("'pushover_user_key' not found in secret, but Pushover is enabled")
		}
	}

	// Return error if any type mismatches occurred during extraction
	if extractErr != nil {
		creds.Zero() // Ensure partial creds are zeroed on error
		return nil, extractErr
	}

	log.Info().Str("component", "vault").Str("path", util.SanitizePath(secretPath)).Msg("Successfully fetched secrets")
	return creds, nil
}

// CreateSnapshot performs a Vault raft snapshot, compresses it, writes checksums, and saves it locally.
// It includes custom retry logic for the snapshot operation.
// Returns the path to the final compressed snapshot file.
func (c *Client) CreateSnapshot(ctx context.Context) (string, error) {
	if c == nil || c.client == nil {
		return "", errors.New("client is not initialized or authenticated")
	}
	cfg := c.config // Use stored config

	// --- 1. Create Temporary File for Raw Snapshot --- //
	// Use the directory of the final snapshot path for the temporary file.
	// Ensure SnapshotPath is a file path, not just a directory.
	if filepath.Ext(cfg.SnapshotPath) == "" {
		return "", fmt.Errorf("SnapshotPath %q must be a full file path (e.g., /path/to/snapshot.snap.gz), not a directory", util.SanitizePath(cfg.SnapshotPath))
	}
	tmpDir := filepath.Dir(cfg.SnapshotPath)
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		// Use sanitized path in error message
		return "", fmt.Errorf("failed to create directory %q for snapshot: %w", util.SanitizePath(tmpDir), err)
	}

	tmpSnapFile, err := os.CreateTemp(tmpDir, "vault-snapshot-*.snap.tmp")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary snapshot file in %q: %w", util.SanitizePath(tmpDir), err)
	}
	tmpSnapFilename := tmpSnapFile.Name()
	sanitizedTmpPath := util.SanitizePath(tmpSnapFilename)
	log.Debug().Str("path", sanitizedTmpPath).Msg("Created temporary file for raw snapshot")

	// Defer cleanup of the temporary raw snapshot file
	defer func() {
		log.Debug().Str("path", sanitizedTmpPath).Msg("Attempting to remove temporary snapshot file")
		if err := tmpSnapFile.Close(); err != nil {
			// Log error, but removal is more important
			log.Warn().Err(err).Str("path", sanitizedTmpPath).Msg("Failed to close temporary snapshot file during cleanup (will still attempt removal)")
		}
		if removeErr := os.Remove(tmpSnapFilename); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			log.Error().Err(removeErr).Str("path", sanitizedTmpPath).Msg("Failed to remove temporary snapshot file")
		} else if removeErr == nil {
			log.Debug().Str("path", sanitizedTmpPath).Msg("Successfully removed temporary snapshot file")
		}
	}()

	// --- 2. Perform Raft Snapshot (with Retries) --- //
	startTime := time.Now()
	var snapshotErr error // Variable to store the final error

	snapshotOperation := func(opCtx context.Context) error {
		// Ensure file is ready for writing (seek/truncate needed if retrying)
		if _, err := tmpSnapFile.Seek(0, io.SeekStart); err != nil {
			// Treat seek/truncate errors as permanent for this operation
			return fmt.Errorf("failed to seek temporary snapshot file %q: %w", sanitizedTmpPath, err) // isTransientVaultError will be false
		}
		if err := tmpSnapFile.Truncate(0); err != nil {
			return fmt.Errorf("failed to truncate temporary snapshot file %q: %w", sanitizedTmpPath, err) // isTransientVaultError will be false
		}

		log.Trace().Str("component", "vault").Msg("Attempting to get Vault Raft snapshot") // Changed to Trace for less noise on retries
		innerErr := c.client.Sys().RaftSnapshotWithContext(opCtx, tmpSnapFile)             // Use opCtx

		if innerErr != nil {
			// Sync before checking error type, might give more context
			_ = tmpSnapFile.Sync()
			// Return the error to be checked by isTransientVaultError
			return innerErr
		}

		// Sync after successful write before returning success
		if err := tmpSnapFile.Sync(); err != nil {
			log.Warn().Err(err).Str("path", sanitizedTmpPath).Msg("Failed to sync temporary snapshot file after write")
			// Treat sync error as permanent for this operation
			return fmt.Errorf("failed to sync snapshot file %q: %w", sanitizedTmpPath, err) // isTransientVaultError will be false
		}
		snapshotErr = nil // Explicitly nil error on success
		return nil        // Success
	}

	// Execute the operation with retry
	snapshotErr = retry.ExecuteWithRetry(ctx, defaultRetryConfig, snapshotOperation, isTransientVaultError, "VaultRaftSnapshot")

	// Check final error after retries
	if snapshotErr != nil {
		log.Error().Err(snapshotErr).Msg("Vault Raft snapshot failed after retries")
		// Cleanup (defer will handle it) and return error
		return "", fmt.Errorf("failed to get Vault raft snapshot: %w", snapshotErr)
	}
	// --- End Retry Block --- //

	duration := time.Since(startTime)
	fileInfo, statErr := tmpSnapFile.Stat()
	if statErr != nil {
		// Should not happen if write succeeded, but check anyway
		return "", fmt.Errorf("failed to stat temporary snapshot file %q after write: %w", sanitizedTmpPath, statErr)
	}
	log.Info().
		Str("component", "vault").
		Str("path", sanitizedTmpPath).
		Int64("size_bytes", fileInfo.Size()).
		Dur("duration", duration).Msg("Raw Vault snapshot saved to temporary file")

	// Close the file descriptor for the temp file now, as we'll reopen it if needed.
	if err := tmpSnapFile.Close(); err != nil {
		// Log error, but proceed to verification/compression if possible
		log.Error().Err(err).Str("path", sanitizedTmpPath).Msg("Failed to close temporary snapshot file after writing (proceeding cautiously)")
		// No need to return here, the file might still be usable. Verification/compression will fail if not.
	}

	// --- 3. Verify Internal Checksums (Optional) --- //
	if !cfg.SkipSnapshotVerify {
		log.Info().Str("component", "vault").Str("path", sanitizedTmpPath).Msg("Verifying internal snapshot checksums")

		// Re-open the temporary file for reading
		verifyFile, err := os.Open(tmpSnapFilename)
		if err != nil {
			return "", fmt.Errorf("failed to re-open temporary snapshot file %q for verification: %w", sanitizedTmpPath, err)
		}

		verified, verifyErr := verifyInternalChecksums(verifyFile) // Pass the open file handle
		closeErr := verifyFile.Close()                             // Close immediately after verification

		if verifyErr != nil {
			// Treat verification error as critical, don't proceed with potentially corrupt backup
			return "", fmt.Errorf("error verifying internal snapshot checksums for %s: %w", sanitizedTmpPath, verifyErr)
		}
		if !verified {
			return "", fmt.Errorf("internal snapshot checksum verification failed for %s", sanitizedTmpPath)
		}
		if closeErr != nil {
			// Log error, but verification passed, so proceed
			log.Warn().Err(closeErr).Str("path", sanitizedTmpPath).Msg("Failed to close temporary snapshot file after verification")
		}
		log.Info().Str("component", "vault").Str("path", sanitizedTmpPath).Msg("Internal snapshot checksums verified successfully")
	} else {
		log.Warn().Str("component", "vault").Msg("Skipping internal snapshot checksum verification")
	}

	// --- 4. Compress Snapshot --- //
	finalPath := cfg.SnapshotPath // This is the full path to the final compressed file
	sanitizedFinalPath := util.SanitizePath(finalPath)
	log.Info().Str("component", "vault").Str("source", sanitizedTmpPath).Str("destination", sanitizedFinalPath).Msg("Compressing snapshot")

	// Open final destination file for writing (use secure permissions)
	outFile, err := os.OpenFile(finalPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("failed to open final snapshot file %q for writing: %w", sanitizedFinalPath, err)
	}
	var closeOutFileErr error
	defer func() {
		if err := outFile.Close(); err != nil {
			closeOutFileErr = err
			log.Error().Err(err).Str("path", sanitizedFinalPath).Msg("Failed to close final snapshot file")
		}
	}()

	gzipWriter := gzip.NewWriter(outFile)
	var closeGzipErr error
	defer func() {
		if err := gzipWriter.Close(); err != nil {
			closeGzipErr = err
			log.Error().Err(err).Str("path", sanitizedFinalPath).Msg("Failed to close gzip writer")
			// Consider deleting the potentially corrupt outFile here if gzip close fails?
			_ = os.Remove(finalPath)
		}
	}()

	// Re-open the temporary file for reading again
	inputFile, err := os.Open(tmpSnapFilename)
	if err != nil {
		return "", fmt.Errorf("failed to re-open temporary snapshot file %q for compression: %w", sanitizedTmpPath, err)
	}
	defer func() { _ = inputFile.Close() }() // Ignore error

	bytesCopied, err := io.Copy(gzipWriter, inputFile)
	if err != nil {
		// Attempt to remove the potentially incomplete/corrupt final file
		_ = os.Remove(finalPath)
		return "", fmt.Errorf("failed to compress snapshot from %s to %s: %w", sanitizedTmpPath, sanitizedFinalPath, err)
	}

	// Explicitly close gzipWriter and outFile *before* checksumming
	// Capture errors from the deferred calls
	if err := gzipWriter.Close(); err != nil {
		closeGzipErr = err
		_ = os.Remove(finalPath)
		return "", fmt.Errorf("failed to close gzip writer for %s: %w", sanitizedFinalPath, err)
	}
	if err := outFile.Close(); err != nil {
		closeOutFileErr = err
		// File might still be valid even if close failed, proceed to checksum? Or return error?
		// Let's return error for now, as a close error is suspicious.
		_ = os.Remove(finalPath)
		return "", fmt.Errorf("failed to close final snapshot file %s after writing: %w", sanitizedFinalPath, err)
	}
	// Check errors captured by defer (should be nil if explicit closes succeeded)
	if closeGzipErr != nil {
		_ = os.Remove(finalPath)
		return "", fmt.Errorf("deferred gzip writer close failed for %s: %w", sanitizedFinalPath, closeGzipErr)
	}
	if closeOutFileErr != nil {
		_ = os.Remove(finalPath)
		return "", fmt.Errorf("deferred final file close failed for %s: %w", sanitizedFinalPath, closeOutFileErr)
	}

	log.Info().Int64("bytes_written_compressed", bytesCopied).Str("path", sanitizedFinalPath).Msg("Snapshot compressed successfully")

	// --- 5. Create Checksum File --- //
	checksumPath := finalPath + ".sha256"
	sanitizedChecksumPath := util.SanitizePath(checksumPath)
	log.Info().Str("component", "vault").Str("snapshot", sanitizedFinalPath).Str("checksum", sanitizedChecksumPath).Msg("Creating checksum file")
	if err := createChecksumFile(finalPath, checksumPath); err != nil {
		// Attempt to remove the snapshot file as well, as it exists without a valid checksum
		_ = os.Remove(finalPath)
		return "", fmt.Errorf("failed to create checksum file %s: %w", sanitizedChecksumPath, err)
	}

	// Cleanup of temp file is handled by defer
	log.Info().Str("component", "vault").Str("path", sanitizedFinalPath).Msg("Snapshot creation complete")
	return finalPath, nil // Return the path to the compressed snapshot
}

// Close revokes the Vault token if it's still valid.
// Should be called deferentially after successful Login.
func (c *Client) Close(ctx context.Context) {
	if c == nil || c.client == nil {
		return // Nothing to close
	}

	token := c.client.Token() // Use interface method
	if token == "" {
		log.Debug().Str("component", "vault").Msg("No Vault token to revoke (client might not have logged in or used token auth)")
		return
	}

	log.Info().Str("component", "vault").Msg("Attempting to revoke Vault token")
	// Use a short, separate context for revocation as the main context might be done.
	revokeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := c.client.Auth().Token().RevokeSelfWithContext(revokeCtx, token) // Use interface method
	if err != nil {
		// Log warning, but don't treat as critical failure of the backup process itself
		// Check if the error is just "token already revoked" or similar non-issue?
		// Vault API might return specific error types or codes here.
		// For now, just log generically.
		log.Warn().Err(err).Msg("Failed to revoke Vault token (this may be expected if token was short-lived or already invalid)")
	} else {
		log.Info().Str("component", "vault").Msg("Vault token revoked successfully")
	}
	// Clear the token in the underlying client if possible? The interface doesn't expose this directly.
	// Setting token to "" might be sufficient via the interface.
	c.client.SetToken("") // Use interface method
	c.client = nil        // Help GC? Or just remove the reference.
}

// --- Helper Functions ---

// verifyInternalChecksums reads a Vault snapshot (tar format) and verifies the checksums inside.
// Expects an open file handle ready for reading at the beginning of the file.
func verifyInternalChecksums(snapshotFile io.ReadSeeker) (bool, error) {
	// Important: Ensure the file pointer is at the beginning before reading
	if _, err := snapshotFile.Seek(0, io.SeekStart); err != nil {
		return false, fmt.Errorf("failed to seek snapshot file: %w", err)
	}

	tarReader := tar.NewReader(snapshotFile) // Works with io.Reader
	filesData := make(map[string][]byte)
	var checksumsContent []byte

	log.Debug().Msg("Extracting snapshot contents for verification")
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return false, fmt.Errorf("failed to read tar header: %w", err)
		}

		if header.Typeflag == tar.TypeReg { // Regular file
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, tarReader); err != nil {
				return false, fmt.Errorf("failed to read file from tar (%s): %w", header.Name, err)
			}
			fileData := buf.Bytes()
			if header.Name == "SHA256SUMS" {
				checksumsContent = fileData
			} else {
				// Store file data, ensuring path separators are consistent (using '/')
				cleanName := filepath.ToSlash(header.Name)
				filesData[cleanName] = fileData
				log.Trace().Str("file", cleanName).Int("size", len(fileData)).Msg("Extracted file from snapshot")
			}
		}
	}

	if checksumsContent == nil {
		return false, fmt.Errorf("SHA256SUMS file not found in the snapshot archive")
	}

	expectedChecksums := parseSHA256SUMS(checksumsContent)
	if len(expectedChecksums) == 0 {
		return false, errors.New("failed to parse SHA256SUMS or it was empty")
	}

	log.Debug().Int("count", len(expectedChecksums)).Msg("Parsed expected checksums")

	if len(filesData) != len(expectedChecksums) {
		log.Warn().Int("files", len(filesData)).Int("checksums", len(expectedChecksums)).Msg("Mismatch between number of files and checksum entries")
		// Depending on strictness, might return false here. Vault might include extra files not in SHA256SUMS?
		// Let's proceed and check the ones listed.
	}

	for filePath, expectedSum := range expectedChecksums {
		log.Trace().Str("file", filePath).Msg("Verifying checksum")
		data, ok := filesData[filePath]
		if !ok {
			log.Error().Str("file", filePath).Msg("File listed in SHA256SUMS not found in archive")
			return false, fmt.Errorf("file %s listed in SHA256SUMS not found in archive", filePath)
		}

		actualSumBytes := sha256.Sum256(data)
		actualSum := fmt.Sprintf("%x", actualSumBytes)

		if actualSum != expectedSum {
			log.Error().Str("file", filePath).Str("expected", expectedSum).Str("actual", actualSum).Msg("Checksum mismatch")
			return false, fmt.Errorf("checksum mismatch for file %s", filePath)
		}
		log.Trace().Str("file", filePath).Msg("Checksum verified")
	}

	log.Debug().Msg("All file checksums in SHA256SUMS verified successfully")
	return true, nil
}

// parseSHA256SUMS parses a file in the format of sha256sum output.
// Example line: "checksum  filename"
func parseSHA256SUMS(content []byte) map[string]string {
	checksums := make(map[string]string)
	lines := bytes.Split(content, []byte("\n")) // Use newline byte slice

	for _, line := range lines {
		trimmedLine := bytes.TrimSpace(line)
		if len(trimmedLine) == 0 {
			continue // Skip empty lines
		}
		parts := bytes.Fields(trimmedLine) // Splits by whitespace
		if len(parts) >= 2 {
			checksum := string(parts[0])
			// Rejoin remaining parts to handle spaces in filenames
			filePath := string(bytes.Join(parts[1:], []byte(" ")))
			// Use filepath.ToSlash for consistent path separators
			checksums[filepath.ToSlash(filePath)] = checksum
		} else if len(parts) > 0 {
			// Log lines that couldn't be parsed correctly
			log.Warn().Str("line", string(line)).Msg("Malformed line in SHA256SUMS: not enough parts")
		}
	}
	return checksums
}

// createChecksumFile calculates the SHA256 checksum of a file and writes it to a new file
// in the format expected by sha256sum.
func createChecksumFile(filePath, checksumPath string) error {
	sanitizedFilePath := util.SanitizePath(filePath)
	sanitizedChecksumPath := util.SanitizePath(checksumPath)
	log.Debug().Str("source", sanitizedFilePath).Str("dest", sanitizedChecksumPath).Msg("Calculating SHA256 checksum")
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file %q for checksum calculation: %w", sanitizedFilePath, err)
	}
	defer func() { _ = file.Close() }() // Ignore error

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("failed to calculate SHA256 checksum for %q: %w", sanitizedFilePath, err)
	}

	checksumHex := fmt.Sprintf("%x", hash.Sum(nil))
	// Format matches `sha256sum` output: checksum<space><space>filename\n
	// Use the base name of the original file for the checksum content
	baseFilename := filepath.Base(filePath)
	content := fmt.Sprintf("%s  %s\n", checksumHex, baseFilename)

	log.Debug().Str("checksum", checksumHex).Str("path", sanitizedChecksumPath).Msg("Writing checksum file")
	// Ensure the file is written securely using OverwriteFile
	if err := util.OverwriteFile(checksumPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("failed to write checksum file %q: %w", sanitizedChecksumPath, err)
	}

	return nil
}
