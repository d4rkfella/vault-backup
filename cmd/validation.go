package cmd

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

func validateConfig() *ValidationError {
	err := &ValidationError{
		Sections: make(map[string]*ValidationSection),
		ExitCode: 1,
	}

	s3Section := &ValidationSection{}
	requiredS3 := map[string]string{
		"s3_access_key": "Missing S3 Access Key (--s3-access-key)",
		"s3_secret_key": "Missing S3 Secret Key (--s3-secret-key)",
		"s3_bucket":     "Missing S3 Bucket Name (--s3-bucket)",
	}

	for key, description := range requiredS3 {
		if !viper.IsSet(key) || viper.GetString(key) == "" {
			s3Section.Issues = append(s3Section.Issues, description)
		}
	}

	if len(s3Section.Issues) > 0 {
		var flagNames []string
		flagPattern := regexp.MustCompile(`--[a-z0-9-]+`)
		for _, issueDesc := range s3Section.Issues {
			flag := flagPattern.FindString(issueDesc)
			if flag != "" {
				flagNames = append(flagNames, flag)
			}
		}

		s3Section.Solutions, s3Section.SettingAdvice = generateStandardFixes(flagNames)
		err.Sections["S3 Storage"] = s3Section
	}

	vaultSection := &ValidationSection{}

	switch {
	case viper.GetBool("vault_k8s_auth_enabled"):
		if !viper.IsSet("vault_k8s_role") || viper.GetString("vault_k8s_role") == "" {
			vaultSection.Issues = append(vaultSection.Issues, "Missing Kubernetes Role (--vault-k8s-role) for Vault Auth")
			var specificSolutions []string
			specificSolutions, vaultSection.SettingAdvice = generateStandardFixes([]string{"--vault-k8s-role"})
			vaultSection.Solutions = append(specificSolutions, "Ensure the service account used has appropriate Vault policies.")
		}

	case viper.GetString("vault_token") == "":
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
	}

	if len(vaultSection.Issues) > 0 {
		err.Sections["Vault Authentication"] = vaultSection
	}

	notifySection := &ValidationSection{}
	pushoverAPIKey := viper.GetString("pushover_api_key")
	pushoverUserKey := viper.GetString("pushover_user_key")

	apiKeyRegex := regexp.MustCompile(`^a[A-Za-z0-9]{29}$`)
	userKeyRegex := regexp.MustCompile(`^u[A-Za-z0-9]{29}$`)

	if (pushoverAPIKey != "" && pushoverUserKey == "") || (pushoverAPIKey == "" && pushoverUserKey != "") {
		notifySection.Issues = append(notifySection.Issues, "Both Pushover keys must be provided if one is set (--pushover-api-key, --pushover-user-key)")
		notifySection.Solutions, notifySection.SettingAdvice = generateStandardFixes([]string{
			"--pushover-api-key",
			"--pushover-user-key",
		})
		err.Sections["Notifications"] = notifySection
	} else if pushoverAPIKey != "" && pushoverUserKey != "" {
		apiKeyValid := apiKeyRegex.MatchString(pushoverAPIKey)
		userKeyValid := userKeyRegex.MatchString(pushoverUserKey)

		if !apiKeyValid || !userKeyValid {
			if !apiKeyValid {
				notifySection.Issues = append(notifySection.Issues, "Pushover API key format is invalid (--pushover-api-key)")
			}
			if !userKeyValid {
				notifySection.Issues = append(notifySection.Issues, "Pushover User key format is invalid (--pushover-user-key)")
			}
			notifySection.Solutions = []string{
				"Pushover API key must start with 'a', User key with 'u'.",
				"Both keys must be exactly 30 alphanumeric characters (A-Z, a-z, 0-9).",
			}
			err.Sections["Notifications"] = notifySection
		}
	}

	if len(err.Sections) > 0 {
		return err
	}
	return nil
}

func generateStandardFixes(flagNames []string) (solutions []string, settingAdvice []string) {
	solutions = []string{"Provide the required value(s)"}

	var flagsWithValues []string
	for _, flag := range flagNames {
		flagsWithValues = append(flagsWithValues, flag+" VALUE")
	}
	flagList := strings.Join(flagsWithValues, " ")

	var envVars []string
	for _, flag := range flagNames {
		envVar := strings.ToUpper(strings.ReplaceAll(strings.TrimPrefix(flag, "--"), "-", "_"))
		envVars = append(envVars, envVar+"=VALUE")
	}
	envList := strings.Join(envVars, " ")

	settingAdvice = []string{
		fmt.Sprintf("1. Via flags: %s", flagList),
		fmt.Sprintf("2. Via environment variables: %s", envList),
		"3. Via config file (e.g., ~/.vault-backup.yaml)",
	}

	return
}
