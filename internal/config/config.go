package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	// Import util package for redaction functions
	"github.com/d4rkfella/vault-backup/internal/util"
)

// Config holds the application configuration, loaded from environment variables.
// Exported fields can be accessed from other packages.
type Config struct {
	VaultAddr                string        // Address of the Vault server (e.g., "https://vault.example.com")
	S3Bucket                 string        // Name of the S3 bucket for backups
	AWSEndpoint              string        // Optional: Custom S3-compatible endpoint URL
	AWSRegion                string        // AWS region for the S3 bucket
	VaultKubernetesRole      string        // Optional: Vault Kubernetes auth role name
	VaultKubernetesTokenPath string        // Optional: Path to the Kubernetes service account token file
	VaultSecretPath          string        // Path in Vault KV store to fetch credentials (AWS, Pushover)
	SnapshotPath             string        // Local directory path to store temporary snapshot files
	MemoryLimitRatio         float64       // Ratio of available memory to set as GOMEMLIMIT (0.0-1.0)
	S3ChecksumAlgorithm      string        // Optional: S3 checksum algorithm to use (e.g., "SHA256")
	LogLevel                 string        // Logging level (e.g., "debug", "info", "warn", "error")
	SecureDelete             bool          // Enable secure deletion of local snapshot files (overwrite before remove)
	PushoverEnable           bool          // Enable Pushover notifications
	SkipSnapshotVerify       bool          // Skip internal checksum verification of Vault snapshot
	S3Prefix                 string        // Optional: Prefix for S3 object keys
	RetentionPeriod          time.Duration // Retention period for backups in S3
}

// LoadConfig loads configuration from environment variables, applies defaults,
// validates required fields, and performs basic sanity checks.
func LoadConfig() (*Config, error) {
	// Define required environment variables
	requiredVars := []string{
		"VAULT_ADDR",
		"S3_BUCKET",
		"VAULT_SECRET_PATH",
	}

	// Check if required variables are set
	if err := checkRequiredEnvVars(requiredVars); err != nil {
		return nil, fmt.Errorf("missing required environment variables: %w", err)
	}

	// Load configuration values, using defaults for optional ones
	cfg := &Config{
		VaultAddr:                getEnv("VAULT_ADDR", ""),
		S3Bucket:                 getEnv("S3_BUCKET", ""),
		AWSEndpoint:              getEnv("AWS_ENDPOINT", ""),
		AWSRegion:                getEnv("AWS_REGION", "auto"),
		VaultKubernetesRole:      getEnv("VAULT_KUBERNETES_ROLE", ""),
		VaultKubernetesTokenPath: getEnv("VAULT_KUBERNETES_TOKEN_PATH", ""), // Default is empty, library uses /var/run/...
		VaultSecretPath:          getEnv("VAULT_SECRET_PATH", ""),
		SnapshotPath:             getEnv("SNAPSHOT_PATH", "/tmp"),
		MemoryLimitRatio:         getEnvFloat("MEMORY_LIMIT_RATIO", 0.85),
		S3ChecksumAlgorithm:      strings.ToUpper(getEnv("S3_CHECKSUM_ALGORITHM", "")), // Default to empty (SDK default)
		LogLevel:                 strings.ToLower(getEnv("LOG_LEVEL", "info")),         // Default to info
		SecureDelete:             getEnvBool("SECURE_DELETE", false),
		PushoverEnable:           getEnvBool("PUSHOVER_ENABLE", false),               // Default to false
		SkipSnapshotVerify:       getEnvBool("SKIP_SNAPSHOT_VERIFY", false),          // Default to false
		S3Prefix:                 getEnv("S3_PREFIX", ""),                            // Optional prefix
		RetentionPeriod:          getEnvDuration("RETENTION_PERIOD", 7*24*time.Hour), // Default to 7 days
	}

	// Validate specific field formats and values
	if !strings.HasPrefix(cfg.VaultAddr, "http://") && !strings.HasPrefix(cfg.VaultAddr, "https://") {
		return nil, fmt.Errorf("invalid VAULT_ADDR format: must start with http:// or https://, got: %s", cfg.VaultAddr)
	}

	if cfg.MemoryLimitRatio <= 0 || cfg.MemoryLimitRatio > 1 {
		return nil, fmt.Errorf("invalid MEMORY_LIMIT_RATIO: must be between 0 and 1, got: %f", cfg.MemoryLimitRatio)
	}

	// Validate SnapshotPath is a writable directory
	if err := checkSnapshotPath(cfg.SnapshotPath); err != nil {
		return nil, fmt.Errorf("invalid SNAPSHOT_PATH: %w", err)
	}

	// Validate S3 checksum algorithm if provided
	if cfg.S3ChecksumAlgorithm != "" {
		validChecksums := map[string]bool{"SHA256": true, "SHA1": true, "CRC32": true, "CRC32C": true}
		if _, ok := validChecksums[cfg.S3ChecksumAlgorithm]; !ok {
			return nil, fmt.Errorf("invalid S3_CHECKSUM_ALGORITHM: %s (valid values: SHA256, SHA1, CRC32, CRC32C)", cfg.S3ChecksumAlgorithm)
		}
	}

	// Validate retention period
	if cfg.RetentionPeriod <= 0 {
		return nil, fmt.Errorf("invalid RETENTION_PERIOD: must be positive, got: %v", cfg.RetentionPeriod)
	}

	log.Info().Str("component", "configuration").Msg("Configuration loaded")
	logDebugConfig(cfg) // Log redacted details at debug level

	return cfg, nil
}

// logDebugConfig logs the configuration details at Debug level with redaction.
func logDebugConfig(cfg *Config) {
	log.Debug().
		Str("component", "configuration").
		Str("VaultAddr", util.RedactURL(cfg.VaultAddr)).
		Str("S3Bucket", cfg.S3Bucket).
		Str("AWSEndpoint", util.RedactURL(cfg.AWSEndpoint)).
		Str("AWSRegion", cfg.AWSRegion).
		Str("VaultKubernetesRole", cfg.VaultKubernetesRole).
		Str("VaultKubernetesTokenPath", util.SanitizePath(cfg.VaultKubernetesTokenPath)). // Sanitize path
		Str("VaultSecretPath", util.SanitizePath(cfg.VaultSecretPath)).
		Str("SnapshotPath", util.SanitizePath(cfg.SnapshotPath)).
		Float64("MemoryLimitRatio", cfg.MemoryLimitRatio).
		Str("S3ChecksumAlgorithm", cfg.S3ChecksumAlgorithm).
		Str("LogLevel", cfg.LogLevel).
		Bool("SecureDelete", cfg.SecureDelete).
		Bool("PushoverEnable", cfg.PushoverEnable).
		Bool("SkipSnapshotVerify", cfg.SkipSnapshotVerify).
		Str("S3Prefix", cfg.S3Prefix).
		Dur("RetentionPeriod", cfg.RetentionPeriod).
		Msg("Loaded configuration details (debug)")
}

// --- Helper functions (kept unexported) ---

// getEnv retrieves an environment variable or returns a default value.
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvBool retrieves a boolean environment variable or returns a default value.
func getEnvBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
		log.Warn().Str("key", key).Str("value", value).Msg("Invalid boolean environment variable, using default")
	}
	return defaultValue
}

// checkRequiredEnvVars checks if all specified environment variables are set.
func checkRequiredEnvVars(requiredVars []string) error {
	var missingVars []string
	for _, key := range requiredVars {
		if _, exists := os.LookupEnv(key); !exists {
			missingVars = append(missingVars, key)
		}
	}
	if len(missingVars) > 0 {
		return fmt.Errorf("missing: %s", strings.Join(missingVars, ", "))
	}
	return nil
}

// getEnvFloat retrieves a float64 environment variable or returns a default value.
func getEnvFloat(key string, defaultValue float64) float64 {
	if value, exists := os.LookupEnv(key); exists {
		if floatValue, err := strconv.ParseFloat(value, 64); err == nil {
			return floatValue
		}
		log.Warn().Str("key", key).Str("value", value).Msg("Invalid float environment variable, using default")
	}
	return defaultValue
}

// getEnvDuration retrieves a time.Duration environment variable or returns a default value.
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if valueStr, exists := os.LookupEnv(key); exists {
		if durationValue, err := time.ParseDuration(valueStr); err == nil {
			return durationValue
		}
		log.Warn().Str("key", key).Str("value", valueStr).Msg("Invalid time duration environment variable, using default")
	}
	return defaultValue
}

// checkSnapshotPath verifies that the snapshot path exists and is a writable directory.
func checkSnapshotPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("snapshot path directory '%s' does not exist", path)
		}
		return fmt.Errorf("failed to stat snapshot path '%s': %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("snapshot path '%s' is not a directory", path)
	}

	// Check for write permissions by trying to create a temporary file
	testFile := filepath.Join(path, ".vault-backup-writetest")
	f, err := os.Create(testFile)
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("snapshot path directory '%s' is not writable: permission denied", path)
		}
		return fmt.Errorf("failed to perform write test in snapshot path '%s': %w", path, err)
	}
	_ = f.Close()           // Ignore close error on temporary test file
	_ = os.Remove(testFile) // Ignore remove error on temporary test file

	return nil
}
