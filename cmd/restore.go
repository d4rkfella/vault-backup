package cmd

import (
	"github.com/d4rkfella/vault-backup/internal/app"
	"github.com/d4rkfella/vault-backup/internal/pkg/s3"
	"github.com/d4rkfella/vault-backup/internal/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var forceRestore bool

var runRestore = app.Restore

var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore a vault backup from raft snapshot",
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

		vaultClient, err := vault.NewClient(ctx, vaultCfg)
		if err != nil {
			return err
		}

		s3Client, err := s3.NewClient(ctx, s3Cfg)
		if err != nil {
			return err
		}

		err = runRestore(ctx, vaultClient, s3Client)
		if err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(restoreCmd)

	restoreCmd.Flags().BoolVarP(&forceRestore, "force", "f", false, "force restore")
}
