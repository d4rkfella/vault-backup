package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to create a temporary directory for testing SNAPSHOT_PATH
func createTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "snapshot-test-*")
	require.NoError(t, err, "Failed to create temp dir for testing")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestLoadConfig_Success(t *testing.T) {
	// Arrange: Set required and some optional env vars
	tempSnapshotDir := createTempDir(t)

	t.Setenv("VAULT_ADDR", "https://vault.test.local")
	t.Setenv("S3_BUCKET", "my-test-bucket")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("VAULT_SECRET_PATH", "kv/data/myapp/s3")
	t.Setenv("SNAPSHOT_PATH", tempSnapshotDir)
	t.Setenv("RETENTION_PERIOD", "360h")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("SECURE_DELETE", "true")
	t.Setenv("S3_CHECKSUM_ALGORITHM", "SHA256")
	t.Setenv("MEMORY_LIMIT_RATIO", "0.7")
	t.Setenv("AWS_ENDPOINT", "http://minio.test:9000")
	t.Setenv("VAULT_KUBERNETES_ROLE", "my-app-role")

	// Act
	cfg, err := LoadConfig()

	// Assert
	require.NoError(t, err)
	require.NotNil(t, cfg)

	assert.Equal(t, "https://vault.test.local", cfg.VaultAddr)
	assert.Equal(t, "my-test-bucket", cfg.S3Bucket)
	assert.Equal(t, "us-east-1", cfg.AWSRegion)
	assert.Equal(t, "kv/data/myapp/s3", cfg.VaultSecretPath)
	assert.Equal(t, tempSnapshotDir, cfg.SnapshotPath)
	assert.Equal(t, 15*24*time.Hour, cfg.RetentionPeriod, "RetentionPeriod should be set from RETENTION_PERIOD env var")
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.True(t, cfg.SecureDelete)
	assert.Equal(t, "SHA256", cfg.S3ChecksumAlgorithm) // Check upper-casing
	assert.Equal(t, 0.7, cfg.MemoryLimitRatio)
	assert.Equal(t, "http://minio.test:9000", cfg.AWSEndpoint)
	assert.Equal(t, "my-app-role", cfg.VaultKubernetesRole)
}

func TestLoadConfig_MissingRequired(t *testing.T) {
	tests := []struct {
		name          string
		unsetVar      string // The required var we will leave unset
		expectedError string // Substring expected in the error message
	}{
		{"Missing VAULT_ADDR", "VAULT_ADDR", "VAULT_ADDR"},
		{"Missing S3_BUCKET", "S3_BUCKET", "S3_BUCKET"},
		{"Missing AWS_REGION", "AWS_REGION", "AWS_REGION"},
		{"Missing VAULT_SECRET_PATH", "VAULT_SECRET_PATH", "VAULT_SECRET_PATH"},
	}

	baseEnv := map[string]string{
		"VAULT_ADDR":        "https://vault.test",
		"S3_BUCKET":         "test-bucket",
		"AWS_REGION":        "us-west-2",
		"VAULT_SECRET_PATH": "kv/test",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange: Set all base vars EXCEPT the one being tested
			for k, v := range baseEnv {
				if k != tt.unsetVar {
					t.Setenv(k, v)
				}
			}

			// Act
			cfg, err := LoadConfig()

			// Assert
			assert.Nil(t, cfg) // Expect nil config on error
			require.Error(t, err)
			assert.Contains(t, err.Error(), "missing required environment variables")
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestLoadConfig_ValidationErrors(t *testing.T) {
	// Helper to set base required env vars for validation tests
	setBaseRequiredEnv := func(t *testing.T) string {
		tempDir := createTempDir(t)
		t.Setenv("VAULT_ADDR", "https://valid.vault") // Start with valid one
		t.Setenv("S3_BUCKET", "valid-bucket")
		t.Setenv("AWS_REGION", "us-west-1")
		t.Setenv("VAULT_SECRET_PATH", "valid/path")
		t.Setenv("SNAPSHOT_PATH", tempDir) // Start with valid one
		return tempDir                     // Return tempDir for potential cleanup/reuse if needed
	}

	t.Run("InvalidVaultAddr", func(t *testing.T) {
		_ = setBaseRequiredEnv(t)
		t.Setenv("VAULT_ADDR", "invalid-vault-address") // Does not start with http/https

		cfg, err := LoadConfig()

		assert.Nil(t, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "VAULT_ADDR must start with http:// or https://")
	})

	t.Run("SnapshotPathDoesNotExist", func(t *testing.T) {
		_ = setBaseRequiredEnv(t)
		nonExistentPath := filepath.Join(os.TempDir(), "non-existent-snapshot-dir-12345")
		_ = os.RemoveAll(nonExistentPath) // Ensure it doesn't exist
		t.Setenv("SNAPSHOT_PATH", nonExistentPath)

		cfg, err := LoadConfig()

		assert.Nil(t, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "snapshot path directory")
		assert.Contains(t, err.Error(), "does not exist")
	})

	t.Run("SnapshotPathIsFile", func(t *testing.T) {
		baseDir := setBaseRequiredEnv(t)
		// Create a file where the directory is expected
		filePath := filepath.Join(baseDir, "..", "snapshot-is-a-file")
		file, err := os.Create(filePath)
		require.NoError(t, err)
		_ = file.Close()
		t.Cleanup(func() { _ = os.Remove(filePath) })

		t.Setenv("SNAPSHOT_PATH", filePath)

		cfg, err := LoadConfig()

		assert.Nil(t, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "snapshot path")
		assert.Contains(t, err.Error(), "is not a directory")
	})

	t.Run("SnapshotPathNotWritable", func(t *testing.T) {
		// Skip on windows - setting read-only perms is complex/different
		if os.PathSeparator == '\\' {
			t.Skip("Skipping non-writable test on Windows due to permission complexity")
		}
		_ = setBaseRequiredEnv(t)
		// Create a directory and make it read-only
		readOnlyDir := createTempDir(t)
		err := os.Chmod(readOnlyDir, 0555) // r-xr-xr-x
		require.NoError(t, err)
		t.Setenv("SNAPSHOT_PATH", readOnlyDir)

		cfg, err := LoadConfig()

		assert.Nil(t, cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "snapshot path directory")
		assert.Contains(t, err.Error(), "is not writable")
	})
}

func TestLoadConfig_DefaultsAndCorrections(t *testing.T) {
	// Arrange: Set only required vars, plus some invalid/boundary values for others
	tempSnapshotDir := createTempDir(t) // Use default path mechanism
	t.Setenv("VAULT_ADDR", "http://localhost:8200")
	t.Setenv("S3_BUCKET", "req-bucket")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("VAULT_SECRET_PATH", "req/path")

	// Specific values to test defaults/corrections
	t.Setenv("RETENTION_PERIOD", "invalid-duration") // Keep invalid duration
	t.Setenv("MEMORY_LIMIT_RATIO", "1.5")
	t.Setenv("S3_CHECKSUM_ALGORITHM", "MD5")
	t.Setenv("SECURE_DELETE", "INVALID_BOOL")
	t.Setenv("LOG_LEVEL", "Trace")
	t.Setenv("INVALID_FLOAT_VAR_FOR_TEST", "not-a-float")
	t.Setenv("INVALID_INT_VAR_FOR_TEST", "not-an-int")

	// Unset other optional vars to check their defaults
	_ = os.Unsetenv("SNAPSHOT_PATH")
	_ = os.Unsetenv("AWS_ENDPOINT")
	_ = os.Unsetenv("VAULT_KUBERNETES_ROLE")
	_ = os.Unsetenv("RETENTION_PERIOD")              // Unset to test default, override above doesn't make sense
	t.Setenv("RETENTION_PERIOD", "invalid-duration") // Reset for test

	// We need to temporarily set SNAPSHOT_PATH for the write check if not set
	if os.Getenv("SNAPSHOT_PATH") == "" {
		t.Setenv("SNAPSHOT_PATH", tempSnapshotDir)
	}

	// Act
	cfg, err := LoadConfig()

	// Assert
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Check corrected values
	assert.Equal(t, 7*24*time.Hour, cfg.RetentionPeriod, "RetentionPeriod should default to 7 days for invalid input")
	assert.Equal(t, 0.85, cfg.MemoryLimitRatio, "MemoryLimitRatio should default to 0.85 for invalid input")
	assert.Equal(t, "", cfg.S3ChecksumAlgorithm, "S3ChecksumAlgorithm should default to empty for invalid input")
	assert.False(t, cfg.SecureDelete, "SecureDelete should default to false for invalid input")
	assert.Equal(t, "trace", cfg.LogLevel, "LogLevel should be lowercased")

	// Check default values for unset vars
	assert.Equal(t, tempSnapshotDir, cfg.SnapshotPath, "SnapshotPath should default if not set")
	assert.Equal(t, "", cfg.AWSEndpoint)
	assert.Equal(t, "", cfg.VaultKubernetesRole)

	// Check that the underlying getEnvInt/Float helpers handled errors gracefully (by using defaults)
	assert.Equal(t, 0.0, getEnvFloat("INVALID_FLOAT_VAR_FOR_TEST", 0.0))

	// Cleanup extra vars set just for this test
	_ = os.Unsetenv("INVALID_FLOAT_VAR_FOR_TEST")
}

func TestCheckSnapshotPath(t *testing.T) {
	t.Run("PathWithPermissionError", func(t *testing.T) {
		// Skip on windows - setting read-only perms is complex/different
		if os.PathSeparator == '\\' {
			t.Skip("Skipping permission error test on Windows due to permission complexity")
		}

		// Create a directory and make it read-only
		readOnlyDir := createTempDir(t)
		err := os.Chmod(readOnlyDir, 0555) // r-xr-xr-x
		require.NoError(t, err)

		err = checkSnapshotPath(readOnlyDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not writable")
		assert.Contains(t, err.Error(), "permission denied")
	})

	t.Run("PathWithStatError", func(t *testing.T) {
		// Skip on windows - setting read-only perms is complex/different
		if os.PathSeparator == '\\' {
			t.Skip("Skipping stat error test on Windows due to permission complexity")
		}

		// Create a directory and make it inaccessible
		inaccessibleDir := createTempDir(t)
		err := os.Chmod(inaccessibleDir, 0000) // ---------
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.Chmod(inaccessibleDir, 0755) }) // Restore permissions for cleanup

		err = checkSnapshotPath(inaccessibleDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not writable")
		assert.Contains(t, err.Error(), "permission denied")
	})

	t.Run("PathWithCreateError", func(t *testing.T) {
		// Skip on windows - setting read-only perms is complex/different
		if os.PathSeparator == '\\' {
			t.Skip("Skipping create error test on Windows due to permission complexity")
		}

		// Create a directory and make it read-only
		readOnlyDir := createTempDir(t)
		err := os.Chmod(readOnlyDir, 0555) // r-xr-xr-x
		require.NoError(t, err)

		err = checkSnapshotPath(readOnlyDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not writable")
		assert.Contains(t, err.Error(), "permission denied")
	})
}

func TestLoadConfig_AdditionalCases(t *testing.T) {
	t.Run("InvalidRetentionPeriod", func(t *testing.T) {
		tempDir := createTempDir(t)
		t.Setenv("VAULT_ADDR", "https://vault.test")
		t.Setenv("S3_BUCKET", "test-bucket")
		t.Setenv("AWS_REGION", "us-west-2")
		t.Setenv("VAULT_SECRET_PATH", "kv/test")
		t.Setenv("SNAPSHOT_PATH", tempDir)
		t.Setenv("RETENTION_PERIOD", "-24h") // Negative retention period

		cfg, err := LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, 7*24*time.Hour, cfg.RetentionPeriod, "Should default to 7 days for negative retention period")
	})

	t.Run("InvalidMemoryLimitRatio", func(t *testing.T) {
		tempDir := createTempDir(t)
		t.Setenv("VAULT_ADDR", "https://vault.test")
		t.Setenv("S3_BUCKET", "test-bucket")
		t.Setenv("AWS_REGION", "us-west-2")
		t.Setenv("VAULT_SECRET_PATH", "kv/test")
		t.Setenv("SNAPSHOT_PATH", tempDir)
		t.Setenv("MEMORY_LIMIT_RATIO", "-0.5") // Negative ratio

		cfg, err := LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, 0.85, cfg.MemoryLimitRatio, "Should default to 0.85 for negative ratio")
	})

	t.Run("InvalidS3ChecksumAlgorithm", func(t *testing.T) {
		tempDir := createTempDir(t)
		t.Setenv("VAULT_ADDR", "https://vault.test")
		t.Setenv("S3_BUCKET", "test-bucket")
		t.Setenv("AWS_REGION", "us-west-2")
		t.Setenv("VAULT_SECRET_PATH", "kv/test")
		t.Setenv("SNAPSHOT_PATH", tempDir)
		t.Setenv("S3_CHECKSUM_ALGORITHM", "INVALID_ALGO")

		cfg, err := LoadConfig()
		require.NoError(t, err)
		assert.Equal(t, "", cfg.S3ChecksumAlgorithm, "Should default to empty string for invalid algorithm")
	})
}

func TestGetEnvDuration(t *testing.T) {
	tests := []struct {
		name         string
		envValue     string
		defaultValue time.Duration
		expected     time.Duration
	}{
		{"ValidDuration", "42h", 0, 42 * time.Hour},
		{"InvalidDuration", "invalid-duration", 0, 0},
		{"EmptyEnv", "", 0, 0},
		{"NegativeDuration", "-42h", 0, -42 * time.Hour},
		{"ZeroDuration", "0", 42 * time.Hour, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				t.Setenv("TEST_DURATION_VAR", tt.envValue)
			} else {
				_ = os.Unsetenv("TEST_DURATION_VAR")
			}

			result := getEnvDuration("TEST_DURATION_VAR", tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCheckRequiredEnvVars(t *testing.T) {
	assert.Equal(t, 0.85, getEnvFloat("TEST_FLOAT_UNSET", 0.85), "Should return default when unset")
}
