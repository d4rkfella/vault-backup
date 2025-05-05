package cmd

import (
	"github.com/d4rkfella/vault-backup/internal/app"
	"github.com/d4rkfella/vault-backup/internal/pkg/notify"
	"github.com/d4rkfella/vault-backup/internal/pkg/s3"
	"github.com/d4rkfella/vault-backup/internal/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup vault secrets using raft snapshot",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		vaultCfg := &vault.Config{
			Address:        viper.GetString("vault_address"),
			Token:          viper.GetString("vault_token"),
			Namespace:      viper.GetString("vault_namespace"),
			Timeout:        viper.GetDuration("vault_timeout"),
			RevokeToken:    viper.GetBool("vault_revoke_token"),
			K8sAuthEnabled: viper.GetBool("vault_k8s_auth_enabled"),
			K8sAuthPath:    viper.GetString("vault_k8s_auth_path"),
			K8sTokenPath:   viper.GetString("vault_k8s_token_path"),
			K8sRole:        viper.GetString("vault_k8s_role"),
			ForceRestore:   forceRestore,
			CACert:         viper.GetString("vault_ca_cert"),
		}

		s3Cfg := &s3.Config{
			AccessKey:       viper.GetString("s3_access_key"),
			SecretAccessKey: viper.GetString("s3_secret_key"),
			Region:          viper.GetString("s3_region"),
			Bucket:          viper.GetString("s3_bucket"),
			Endpoint:        viper.GetString("s3_endpoint"),
			SessionToken:    viper.GetString("s3_session_token"),
			FileName:        viper.GetString("s3_filename"),
		}

		var notifyCfg *notify.Config
		if pushoverAPIKey != "" && pushoverUserKey != "" {
			notifyCfg = &notify.Config{
				APIKey:  pushoverAPIKey,
				UserKey: pushoverUserKey,
			}
		}
		return app.Backup(ctx, vaultCfg, s3Cfg, notifyCfg)
	},
}

func init() {
	rootCmd.AddCommand(backupCmd)
}
