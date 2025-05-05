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

var revokeToken bool

var runBackup = app.Backup

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Perform a vault backup and stores it as raft snapshot",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		vaultCfg := &vault.Config{
			Address:        viper.GetString("vault_address"),
			Token:          viper.GetString("vault_token"),
			Namespace:      viper.GetString("vault_namespace"),
			Timeout:        viper.GetDuration("vault_timeout"),
			RevokeToken:    revokeToken,
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

		var notifyCfg *pushover.Config
		pkey := viper.GetString("notify_pushover_api_key")
		ukey := viper.GetString("notify_pushover_user_key")
		if pkey != "" && ukey != "" {
			notifyCfg = &pushover.Config{
				APIKey:  pkey,
				UserKey: ukey,
			}
		}

		vaultClient, err := vault.NewClient(ctx, vaultCfg)
		if err != nil {
			return fmt.Errorf("failed to initialize vault client: %w", err)
		}

		s3Client, err := s3.NewClient(ctx, s3Cfg)
		if err != nil {
			return fmt.Errorf("failed to initialize s3 client: %w", err)
		}

		var appNotifyClient app.NotifyClient
		if notifyCfg != nil {
			appNotifyClient = pushover.NewClient(notifyCfg)
		}

		return runBackup(ctx, vaultClient, s3Client, appNotifyClient, vaultCfg.RevokeToken)
	},
}

func init() {
	rootCmd.AddCommand(backupCmd)

	backupCmd.Flags().BoolVar(&revokeToken, "revoke-token", false, "Revoke the vault token after backup completes")
}
