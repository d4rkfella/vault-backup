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
	"strings"
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

	// Debug log the secret data structure
	log.Debug().Interface("secret_data", secret.Data).Msg("Raw secret data from Vault")

	// Handle KV v2 secrets - check for data field
	data := secret.Data
	if v2Data, exists := data["data"]; exists {
		// Check if v2Data is a map[string]interface{}
		v2Map, ok := v2Data.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid data structure in KV v2 secret at path %s: data field is not a map", util.SanitizePath(secretPath))
		}
		if v2Map == nil {
			return nil, fmt.Errorf("invalid data structure in KV v2 secret at path %s: data field is nil", util.SanitizePath(secretPath))
		}
		data = v2Map
		log.Debug().Interface("kv2_data", data).Msg("KV v2 data extracted")
	}

	// Extract data into SecureString fields
	creds := &VaultCredentials{}
	var ok bool
	var awsAccess, awsSecret, pushAPI, pushUser string

	// Helper function to extract and zero string
	extract := func(key string) (string, bool) {
		val, exists := data[key]
		if !exists {
			return "", false
		}
		strVal, ok := val.(string)
		if !ok {
			log.Error().Str("key", key).Str("path", util.SanitizePath(secretPath)).Msg("Invalid type for key in secret")
			// Mark as not ok, but don't return error immediately, allows processing other keys
			return "", false
		}
		return strings.TrimSpace(strVal), true
	}

	var extractErr error // Keep track of extraction errors

	if awsAccess, ok = extract("aws_access_key"); ok {
		creds.AWSAccess = NewSecureString([]byte(awsAccess))
		defer zeroBytes([]byte(awsAccess)) // Zero intermediate string bytes
	} else if _, exists := data["aws_access_key"]; exists && !ok { // Only error if key exists but type is wrong
		extractErr = errors.Join(extractErr, fmt.Errorf("invalid type for 'aws_access_key' in secret %s", util.SanitizePath(secretPath)))
	} else { // Key doesn't exist
		log.Warn().Str("path", util.SanitizePath(secretPath)).Msg("'aws_access_key' not found in secret")
	}

	if awsSecret, ok = extract("aws_secret_key"); ok {
		creds.AWSSecret = NewSecureString([]byte(awsSecret))
		defer zeroBytes([]byte(awsSecret))
	} else if _, exists := data["aws_secret_key"]; exists && !ok {
		extractErr = errors.Join(extractErr, fmt.Errorf("invalid type for 'aws_secret_key' in secret %s", util.SanitizePath(secretPath)))
	} else {
		log.Warn().Str("path", util.SanitizePath(secretPath)).Msg("'aws_secret_key' not found in secret")
	}

	if pushAPI, ok = extract("pushover_api_token"); ok {
		creds.PushoverAPI = NewSecureString([]byte(pushAPI))
		defer zeroBytes([]byte(pushAPI))
	} else if _, exists := data["pushover_api_token"]; exists && !ok {
		extractErr = errors.Join(extractErr, fmt.Errorf("invalid type for 'pushover_api_token' in secret %s", util.SanitizePath(secretPath)))
	} else {
		if c.config.PushoverEnable {
			log.Warn().Str("path", util.SanitizePath(secretPath)).Msg("'pushover_api_token' not found in secret, but Pushover is enabled")
		}
	}

	if pushUser, ok = extract("pushover_user_id"); ok {
		creds.PushoverUser = NewSecureString([]byte(pushUser))
		defer zeroBytes([]byte(pushUser))
	} else if _, exists := data["pushover_user_id"]; exists && !ok {
		extractErr = errors.Join(extractErr, fmt.Errorf("invalid type for 'pushover_user_id' in secret %s", util.SanitizePath(secretPath)))
	} else {
		if c.config.PushoverEnable {
			log.Warn().Str("path", util.SanitizePath(secretPath)).Msg("'pushover_user_id' not found in secret, but Pushover is enabled")
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

	// --- 1. Validate Snapshot Directory and Generate Filename --- //
	sanitizedDir := util.SanitizePath(cfg.SnapshotPath)
	pathInfo, pathErr := os.Stat(cfg.SnapshotPath)

	if pathErr != nil {
		if errors.Is(pathErr, os.ErrNotExist) {
			return "", fmt.Errorf("snapshot directory %q does not exist", sanitizedDir)
		} else {
			return "", fmt.Errorf("failed to stat snapshot directory %q: %w", sanitizedDir, pathErr)
		}
	}
	if !pathInfo.IsDir() {
		return "", fmt.Errorf("snapshot path %q is not a directory", sanitizedDir)
	}

	// Generate filename
	now := time.Now()
	filename := fmt.Sprintf("vault-snapshot-%s.snap", now.Format("20060102-150405"))
	finalPath := filepath.Join(cfg.SnapshotPath, filename)
	sanitizedFinalPath := util.SanitizePath(finalPath)
	log.Info().Str("path", sanitizedFinalPath).Msg("Creating snapshot")

	// Create the snapshot file
	file, err := os.Create(finalPath)
	if err != nil {
		return "", fmt.Errorf("failed to create snapshot file %q: %w", sanitizedFinalPath, err)
	}
	defer file.Close()

	// Take the snapshot with retries
	var snapshotErr error
	for retries := 0; retries < 3; retries++ {
		if retries > 0 {
			log.Info().Int("retry", retries).Msg("Retrying snapshot creation")
			time.Sleep(time.Second * time.Duration(retries))
		}

		if err := c.client.Sys().RaftSnapshotWithContext(ctx, file); err != nil {
			snapshotErr = err
			if !isTransientVaultError(err) {
				_ = os.Remove(finalPath)
				return "", fmt.Errorf("failed to create Vault snapshot: %w", err)
			}
			continue
		}
		snapshotErr = nil
		break
	}

	if snapshotErr != nil {
		_ = os.Remove(finalPath)
		return "", fmt.Errorf("failed to create Vault snapshot: %w", snapshotErr)
	}

	// Verify internal checksums
	if !cfg.SkipSnapshotVerify {
		log.Info().Str("component", "vault").Str("path", sanitizedFinalPath).Msg("Verifying internal snapshot checksums")
		verified, verifyErr := verifyInternalChecksums(finalPath)
		if verifyErr != nil {
			_ = os.Remove(finalPath)
			return "", fmt.Errorf("error verifying internal snapshot checksums for %s: %w", sanitizedFinalPath, verifyErr)
		}
		if !verified {
			_ = os.Remove(finalPath)
			return "", fmt.Errorf("internal snapshot checksum verification failed for %s", sanitizedFinalPath)
		}
		log.Info().Str("component", "vault").Str("path", sanitizedFinalPath).Msg("Internal snapshot checksums verified successfully")
	} else {
		log.Warn().Str("component", "vault").Msg("Skipping internal snapshot checksum verification")
	}

	log.Info().Str("component", "vault").Str("path", sanitizedFinalPath).Msg("Snapshot creation complete")
	return finalPath, nil
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

// verifyInternalChecksums reads a Vault snapshot (tar.gz format) and verifies the checksums inside.
// Expects the full path to the gzipped snapshot file.
func verifyInternalChecksums(snapshotGzipPath string) (bool, error) {
	// Open the gzipped snapshot file
	sanitizedPath := util.SanitizePath(snapshotGzipPath)
	file, err := os.Open(snapshotGzipPath)
	if err != nil {
		return false, fmt.Errorf("failed to open snapshot file %q: %w", sanitizedPath, err)
	}
	defer file.Close()

	// Create a gzip reader
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		// If it's not even valid gzip, it can't contain the expected tar archive
		return false, fmt.Errorf("failed to create gzip reader for %q: %w", sanitizedPath, err)
	}
	defer gzReader.Close()

	// Create a tar reader on top of the gzip reader
	tarReader := tar.NewReader(gzReader)
	filesData := make(map[string][]byte)
	var checksumsContent []byte
	foundChecksumFile := false

	log.Debug().Msg("Extracting snapshot contents for verification")
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			// Check for common tar errors like unexpected EOF which might occur with malformed archives
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return false, fmt.Errorf("failed to read tar header (unexpected EOF) from %q: %w", sanitizedPath, err)
			}
			return false, fmt.Errorf("failed to read tar header from %q: %w", sanitizedPath, err)
		}

		if header.Typeflag == tar.TypeReg { // Regular file
			// Limit the amount read per file to prevent memory exhaustion from large unexpected files
			limitedReader := io.LimitedReader{R: tarReader, N: 1024 * 1024 * 100} // 100MB limit per file inside tar
			var buf bytes.Buffer
			if _, err := io.Copy(&buf, &limitedReader); err != nil {
				return false, fmt.Errorf("failed to read file content from tar (%s) in %q: %w", header.Name, sanitizedPath, err)
			}
			fileData := buf.Bytes()
			if header.Name == "SHA256SUMS" {
				checksumsContent = fileData
				foundChecksumFile = true
			} else {
				// Store file data, ensuring path separators are consistent (using '/')
				cleanName := filepath.ToSlash(header.Name)
				filesData[cleanName] = fileData
				log.Trace().Str("file", cleanName).Int("size", len(fileData)).Msg("Extracted file from snapshot")
			}
		}
	}

	if !foundChecksumFile {
		return false, fmt.Errorf("SHA256SUMS file not found in the snapshot archive %q", sanitizedPath)
	}

	expectedChecksums := parseSHA256SUMS(checksumsContent)
	if len(expectedChecksums) == 0 {
		return false, fmt.Errorf("failed to parse SHA256SUMS or it was empty in %q", sanitizedPath)
	}

	log.Debug().Int("count", len(expectedChecksums)).Msg("Parsed expected checksums")

	if len(filesData) != len(expectedChecksums) {
		log.Warn().Int("files", len(filesData)).Int("checksums", len(expectedChecksums)).Msg("Mismatch between number of files and checksum entries")
		// Allow this for now, just verify the files listed in SHA256SUMS
	}

	for filePath, expectedSum := range expectedChecksums {
		log.Trace().Str("file", filePath).Msg("Verifying checksum")
		data, ok := filesData[filePath]
		if !ok {
			log.Error().Str("file", filePath).Msg("File listed in SHA256SUMS not found in archive")
			return false, fmt.Errorf("file %s listed in SHA256SUMS not found in archive %q", filePath, sanitizedPath)
		}

		actualSumBytes := sha256.Sum256(data)
		actualSum := fmt.Sprintf("%x", actualSumBytes)

		if actualSum != expectedSum {
			log.Error().Str("file", filePath).Str("expected", expectedSum).Str("actual", actualSum).Msg("Checksum mismatch")
			return false, fmt.Errorf("checksum mismatch for file %s in %q", filePath, sanitizedPath)
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

