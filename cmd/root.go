package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	cfgFile         string
	vaultAddr       string
	vaultToken      string
	vaultNamespace  string
	vaultTimeout    time.Duration
	vaultCACert     string
	k8sAuthEnabled  bool
	k8sAuthPath     string
	k8sTokenPath    string
	k8sRole         string
	s3AccessKey     string
	s3SecretKey     string
	s3Bucket        string
	s3Region        string
	s3Endpoint      string
	s3FileName      string
	pushoverAPIKey  string
	pushoverUserKey string
)

var version = "dev"

var rootCmd = &cobra.Command{
	Use:           "vault-backup",
	Short:         "vault-backup is a CLI tool to backup and restore Vault data using raft snapshots.",
	SilenceErrors: true,
	SilenceUsage:  true,
	Version:       version,
	Run: func(cmd *cobra.Command, args []string) {
		if err := cmd.Help(); err != nil {
			fmt.Fprintf(os.Stderr, "error displaying help: %v\n", err)
			os.Exit(1)
		}
	},
}

func ExecuteContext(ctx context.Context) {
	cobra.CheckErr(rootCmd.ExecuteContext(ctx))
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vault-backup.yaml)")

	rootCmd.PersistentFlags().StringVarP(&vaultAddr, "vault-address", "a", "http://localhost:8200", "Vault server address")
	rootCmd.PersistentFlags().StringVarP(&vaultNamespace, "vault-namespace", "n", "", "Vault namespace")
	rootCmd.PersistentFlags().StringVarP(&vaultToken, "vault-token", "t", "", "Vault token")
	rootCmd.PersistentFlags().DurationVar(&vaultTimeout, "vault-timeout", 30*time.Second, "Vault client timeout")
	rootCmd.PersistentFlags().StringVar(&vaultCACert, "vault-ca-cert", "", "Path to the Vault CA certificate file")

	rootCmd.PersistentFlags().BoolVar(&k8sAuthEnabled, "vault-k8s-auth-enabled", false, "Enable Kubernetes authentication")
	rootCmd.PersistentFlags().StringVar(&k8sAuthPath, "vault-k8s-auth-path", "kubernetes", "Kubernetes auth mount path")
	rootCmd.PersistentFlags().StringVar(&k8sTokenPath, "vault-k8s-token-path", "/var/run/secrets/kubernetes.io/serviceaccount/token", "Kubernetes service account token mount path")
	rootCmd.PersistentFlags().StringVar(&k8sRole, "vault-k8s-role", "", "Kubernetes role for authentication")

	rootCmd.PersistentFlags().StringVar(&s3AccessKey, "s3-access-key", "", "S3 access key")
	rootCmd.PersistentFlags().StringVar(&s3SecretKey, "s3-secret-key", "", "S3 secret key")
	rootCmd.PersistentFlags().StringVar(&s3Bucket, "s3-bucket", "", "S3 bucket name")
	rootCmd.PersistentFlags().StringVar(&s3Region, "s3-region", "us-east-1", "S3 region")
	rootCmd.PersistentFlags().StringVar(&s3Endpoint, "s3-endpoint", "", "S3 endpoint URL")
	rootCmd.PersistentFlags().StringVar(&s3FileName, "s3-filename", "", "S3 filename")

	rootCmd.PersistentFlags().StringVar(&pushoverAPIKey, "pushover-api-key", "", "Pushover API key")
	rootCmd.PersistentFlags().StringVar(&pushoverUserKey, "pushover-user-key", "", "Pushover user key")

	err := rootCmd.MarkPersistentFlagRequired("s3-access-key")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marking flag as required: %v\n", err)
	}

	bindFlags(rootCmd)
}

func initConfig() {
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".vault-backup")
	}

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintln(os.Stderr, "Error reading config file:", err)
		}
	}

	bindFlags(rootCmd)
}

func bindFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		configName := strings.ReplaceAll(f.Name, "-", "_")

		if err := viper.BindPFlag(configName, f); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to bind flag %q to viper key %q: %v\n", f.Name, configName, err)
		}

		envVar := strings.ToUpper(configName)
		if err := viper.BindEnv(configName, envVar); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to bind flag %q to env var %q: %v\n", f.Name, envVar, err)
		}

		if !f.Changed && viper.IsSet(configName) {
			val := viper.Get(configName)
			if err := cmd.PersistentFlags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
				fmt.Fprintf(os.Stderr, "warning: failed to set flag %q from viper key %q (%v): %v\n", f.Name, configName, val, err)
			}
		}
	})
}
