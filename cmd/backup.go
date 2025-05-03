package cmd

import (
	"context"
	"time"

	"github.com/d4rkfella/vault-backup/internal/app"
	"github.com/d4rkfella/vault-backup/internal/pkg/notify"
	"github.com/d4rkfella/vault-backup/internal/pkg/s3"
	"github.com/d4rkfella/vault-backup/internal/pkg/vault"
	"github.com/spf13/cobra"
)

// backupCmd represents the backup command
var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup vault secrets using raft snapshot",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		// Create Vault config
		vaultConfig := &vault.Config{
			Address:   vaultAddr,
			Token:     vaultToken,
			Namespace: vaultNamespace,
			Timeout:   vaultTimeout,
		}

		// Create S3 config
		s3Config := &s3.Config{
			Bucket:          s3Bucket,
			Region:          s3Region,
			Endpoint:        s3Endpoint,
			AccessKey:       s3AccessKey,
			SecretAccessKey: s3SecretKey,
		}

		// Create notification config if credentials are provided
		var notifyConfig *notify.Config
		if pushoverAPIKey != "" && pushoverUserKey != "" {
			notifyConfig = &notify.Config{
				APIKey:  pushoverAPIKey,
				UserKey: pushoverUserKey,
			}
		}

		// Create backup config
		backupConfig := app.BackupConfig{
			VaultConfig:  vaultConfig,
			S3Config:     s3Config,
			NotifyConfig: notifyConfig,
		}

		// Execute backup with context
		return app.Backup(ctx, backupConfig)
	},
}

func init() {
	rootCmd.AddCommand(backupCmd)
}
