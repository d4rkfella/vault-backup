package cmd

import (
	"fmt"

	"github.com/d4rkfella/vault-backup/internal/app"
	"github.com/d4rkfella/vault-backup/internal/pkg/pushover"
	"github.com/d4rkfella/vault-backup/internal/pkg/s3"
	"github.com/d4rkfella/vault-backup/internal/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var runBackup = app.Backup

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Perform a vault backup and stores it as raft snapshot",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if verr := validateConfig(); verr != nil {
			cmd.Println()
			verr.Exit()
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		vaultCfg := &vault.Config{
			Address:        viper.GetString("vault_address"),
			Token:          viper.GetString("vault_token"),
			Namespace:      viper.GetString("vault_namespace"),
			Timeout:        viper.GetDuration("vault_timeout"),
			K8sAuthEnabled: viper.GetBool("vault_k8s_auth_enabled"),
			K8sAuthPath:    viper.GetString("vault_k8s_auth_path"),
			K8sTokenPath:   viper.GetString("vault_k8s_token_path"),
			K8sRole:        viper.GetString("vault_k8s_role"),
			CACert:         viper.GetString("vault_ca_cert"),
		}

		s3Cfg := &s3.Config{
			AccessKey:       viper.GetString("s3_access_key"),
			SecretAccessKey: viper.GetString("s3_secret_key"),
			Region:          viper.GetString("s3_region"),
			Bucket:          viper.GetString("s3_bucket"),
			Endpoint:        viper.GetString("s3_endpoint"),
			SessionToken:    viper.GetString("s3_session_token"),
		}

		var pushoverCfg *pushover.Config
		pkey := viper.GetString("pushover_api_key")
		ukey := viper.GetString("pushover_user_key")
		if pkey != "" && ukey != "" {
			pushoverCfg = &pushover.Config{
				APIKey:  pkey,
				UserKey: ukey,
			}
		}

		vaultClient, err := vault.NewClient(ctx, vaultCfg)
		if err != nil {
			return fmt.Errorf("failed to initialize vault client for backup: %w", err)
		}

		s3Client, err := s3.NewClient(ctx, s3Cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize s3 client for backup: %w", err)
		}

		var pushoverClient app.NotifyClient
		if pushoverCfg != nil {
			pushoverClient = pushover.NewClient(pushoverCfg)
		}

		err = runBackup(ctx, vaultClient, s3Client, pushoverClient)
		if err != nil {
			return fmt.Errorf("backup command failed: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(backupCmd)
}
