package cmd

import (
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to reset viper between tests
func resetViper() {
	viper.Reset()
}

func TestValidateConfig_Valid_TokenAuth(t *testing.T) {
	resetViper()
	vaultToken := "hvs.validtoken"
	s3AccessKey := "accesskey"
	s3SecretKey := "secretkey"
	s3Bucket := "mybucket"

	viper.Set("vault_token", vaultToken)
	viper.Set("s3_access_key", s3AccessKey)
	viper.Set("s3_secret_key", s3SecretKey)
	viper.Set("s3_bucket", s3Bucket)

	verr := validateConfig()
	assert.Nil(t, verr, "Expected no validation error for valid token auth config")
}

func TestValidateConfig_Valid_K8sAuth(t *testing.T) {
	resetViper()
	k8sEnabled := true
	k8sRole := "my-k8s-role"
	s3AccessKey := "accesskey"
	s3SecretKey := "secretkey"
	s3Bucket := "mybucket"

	viper.Set("vault_k8s_auth_enabled", k8sEnabled)
	viper.Set("vault_k8s_role", k8sRole)
	viper.Set("s3_access_key", s3AccessKey)
	viper.Set("s3_secret_key", s3SecretKey)
	viper.Set("s3_bucket", s3Bucket)

	verr := validateConfig()
	assert.Nil(t, verr, "Expected no validation error for valid k8s auth config")
}

func TestValidateConfig_MissingS3(t *testing.T) {
	resetViper()
	vaultToken := "hvs.validtoken"
	viper.Set("vault_token", vaultToken)
	// Missing S3 keys

	verr := validateConfig()
	require.NotNil(t, verr, "Expected validation error for missing S3 config")
	require.Contains(t, verr.Sections, "S3 Storage", "Error should contain S3 Storage section")
	assert.Len(t, verr.Sections["S3 Storage"].Issues, 3, "Expected 3 S3 issues")
	assert.Contains(t, verr.Error(), "Missing S3 Access Key")
	assert.Contains(t, verr.Error(), "Missing S3 Secret Key")
	assert.Contains(t, verr.Error(), "Missing S3 Bucket Name")
}

func TestValidateConfig_MissingVaultAuth(t *testing.T) {
	resetViper()
	// Set valid S3
	vipers3AccessKey := "accesskey"
	s3SecretKey := "secretkey"
	s3Bucket := "mybucket"
	viper.Set("s3_access_key", vipers3AccessKey)
	viper.Set("s3_secret_key", s3SecretKey)
	viper.Set("s3_bucket", s3Bucket)

	// Missing vault auth
	vaultSection := &ValidationSection{}
	vaultSection.Issues = append(vaultSection.Issues, "Missing Vault Authentication Method (Token or Kubernetes)")
	vaultSection.Solutions = []string{
		"Choose ONE authentication method:",
		"  - Option 1 (Static Token): Provide --vault-token",
		"  - Option 2 (Kubernetes Auth): Provide BOTH --vault-k8s-auth-enabled AND --vault-k8s-role",
	}
	_, vaultSection.SettingAdvice = generateStandardFixes([]string{
		"--vault-token",
		"--vault-k8s-auth-enabled",
		"--vault-k8s-role",
	})

	verr := validateConfig()
	require.NotNil(t, verr, "Expected validation error for missing Vault auth")
	require.Contains(t, verr.Sections, "Vault Authentication", "Error should contain Vault Authentication section")
	assert.Len(t, verr.Sections["Vault Authentication"].Issues, 1)
	assert.Contains(t, verr.Error(), "Missing Vault Authentication Method")
}

func TestValidateConfig_MissingK8sRole(t *testing.T) {
	resetViper()
	// Set valid S3
	s3AccessKey := "accesskey"
	s3SecretKey := "secretkey"
	s3Bucket := "mybucket"
	viper.Set("s3_access_key", s3AccessKey)
	viper.Set("s3_secret_key", s3SecretKey)
	viper.Set("s3_bucket", s3Bucket)
	// Enable K8s but miss role
	viper.Set("vault_k8s_auth_enabled", true)

	verr := validateConfig()
	require.NotNil(t, verr, "Expected validation error for missing K8s role")
	require.Contains(t, verr.Sections, "Vault Authentication", "Error should contain Vault Authentication section")
	assert.Len(t, verr.Sections["Vault Authentication"].Issues, 1)
	assert.Contains(t, verr.Error(), "Missing Kubernetes Role")
}

func TestValidateConfig_PushoverOneKeyMissing(t *testing.T) {
	tests := []struct {
		name    string
		apiKey  string
		userKey string
	}{
		{"API Key Only", "aVALIDpushoverapikeyforapp1234", ""},
		{"User Key Only", "", "uVALIDpushoveruserkey123456789"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetViper()
			// Set valid S3 & Vault
			vaultToken := "hvs.validtoken"
			s3AccessKey := "accesskey"
			s3SecretKey := "secretkey"
			s3Bucket := "mybucket"
			viper.Set("vault_token", vaultToken)
			viper.Set("s3_access_key", s3AccessKey)
			viper.Set("s3_secret_key", s3SecretKey)
			viper.Set("s3_bucket", s3Bucket)
			// Set pushover keys
			viper.Set("pushover_api_key", tt.apiKey)
			viper.Set("pushover_user_key", tt.userKey)

			verr := validateConfig()
			require.NotNil(t, verr, "Expected validation error for incomplete Pushover keys")
			require.Contains(t, verr.Sections, "Notifications", "Error should contain Notifications section")
			assert.Len(t, verr.Sections["Notifications"].Issues, 1)
			assert.Contains(t, verr.Error(), "Both Pushover keys must be provided")
		})
	}
}

func TestValidateConfig_PushoverInvalidFormat(t *testing.T) {
	tests := []struct {
		name          string
		apiKey        string
		userKey       string
		expectedCount int
		expectedMsgs  []string
	}{
		{"Invalid API Key", "INVALIDpushoverapikey", "uVALIDpushoveruserkey123456789", 1, []string{"Pushover API key format is invalid"}},
		{"Invalid User Key", "aVALIDpushoverapikeyforapp1234", "INVALIDpushoveruserkey", 1, []string{"Pushover User key format is invalid"}},
		{"Both Invalid", "INVALIDkey1", "INVALIDkey2", 2, []string{"Pushover API key format is invalid", "Pushover User key format is invalid"}},
		{"Valid Keys", "aVALIDpushoverapikeyforapp1234", "uVALIDpushoveruserkey123456789", 0, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetViper()
			// Set valid S3 & Vault
			vaultToken := "hvs.validtoken"
			s3AccessKey := "accesskey"
			s3SecretKey := "secretkey"
			s3Bucket := "mybucket"
			viper.Set("vault_token", vaultToken)
			viper.Set("s3_access_key", s3AccessKey)
			viper.Set("s3_secret_key", s3SecretKey)
			viper.Set("s3_bucket", s3Bucket)
			// Set pushover keys
			viper.Set("pushover_api_key", tt.apiKey)
			viper.Set("pushover_user_key", tt.userKey)

			verr := validateConfig()

			if tt.expectedCount > 0 {
				require.NotNil(t, verr, "Expected validation error for invalid Pushover keys")
				require.Contains(t, verr.Sections, "Notifications", "Error should contain Notifications section")
				assert.Len(t, verr.Sections["Notifications"].Issues, tt.expectedCount)
				for _, msg := range tt.expectedMsgs {
					assert.Contains(t, verr.Error(), msg)
				}
			} else {
				assert.Nil(t, verr, "Expected no validation error for valid Pushover keys")
			}
		})
	}
}

func TestGenerateStandardFixes(t *testing.T) {
	flags := []string{"--s3-access-key", "--s3-secret-key"}
	solutions, advice := generateStandardFixes(flags)

	assert.Len(t, solutions, 1)
	assert.Equal(t, "Provide the required value(s)", solutions[0])

	assert.Len(t, advice, 3)
	assert.Equal(t, "1. Via flags: --s3-access-key VALUE --s3-secret-key VALUE", advice[0])
	assert.Equal(t, "2. Via environment variables: S3_ACCESS_KEY=VALUE S3_SECRET_KEY=VALUE", advice[1])
	assert.Equal(t, "3. Via config file (e.g., ~/.vault-backup.yaml)", advice[2])
}

func TestValidationError_ErrorFormatting(t *testing.T) {
	resetViper()
	// Trigger multiple sections
	viper.Set("pushover_api_key", "apikey_only")

	verr := validateConfig()
	require.NotNil(t, verr)

	output := verr.Error()

	// Check structure
	assert.Regexp(t, regexp.MustCompile(`(?s)🔴 Configuration Errors.*══════════════════════.*■ S3 Storage.*Issue\(s\):.*• Missing S3 Access Key.*■ Notifications.*Issue\(s\):.*• Both Pushover keys must be provided.*══════════════════════`), output)

	// Check indentation and bullets
	lines := strings.Split(output, "\n")
	foundS3Issue := false
	foundNotifyIssue := false
	for _, line := range lines {
		if strings.Contains(line, "Missing S3 Access Key") {
			assert.True(t, strings.HasPrefix(strings.TrimSpace(line), "•"), "S3 issue should start with bullet")
			foundS3Issue = true
		}
		if strings.Contains(line, "Both Pushover keys must be provided") {
			assert.True(t, strings.HasPrefix(strings.TrimSpace(line), "•"), "Notify issue should start with bullet")
			foundNotifyIssue = true
		}
	}
	assert.True(t, foundS3Issue, "S3 issue line not found correctly")
	assert.True(t, foundNotifyIssue, "Notify issue line not found correctly")
}
