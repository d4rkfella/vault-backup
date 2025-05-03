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
	s3AccessKey     string
	s3SecretKey     string
	s3Bucket        string
	s3Region        string
	s3Endpoint      string
	s3FileName      string
	pushoverAPIKey  string
	pushoverUserKey string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "vault-backup",
	Short: "Tool for backing up and restoring Vault using snapshots",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

// SetContext sets the context on the root command
func SetContext(ctx context.Context) {
	rootCmd.SetContext(ctx)
}

func init() {
	cobra.OnInitialize(initConfig)

	// Config file flag
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vault-backup.yaml)")

	// Vault configuration flags
	rootCmd.PersistentFlags().StringVarP(&vaultAddr, "vault-address", "a", "http://localhost:8200", "Vault server address")
	rootCmd.PersistentFlags().StringVarP(&vaultNamespace, "vault-namespace", "n", "", "Vault namespace")
	rootCmd.PersistentFlags().StringVarP(&vaultToken, "vault-token", "t", "", "Vault token")
	rootCmd.PersistentFlags().DurationVar(&vaultTimeout, "vault-timeout", 30*time.Second, "Vault client timeout")

	// S3 configuration flags
	rootCmd.PersistentFlags().StringVar(&s3AccessKey, "s3-access-key", "", "S3 access key")
	rootCmd.PersistentFlags().StringVar(&s3SecretKey, "s3-secret-key", "", "S3 secret key")
	rootCmd.PersistentFlags().StringVar(&s3Bucket, "s3-bucket", "", "S3 bucket name")
	rootCmd.PersistentFlags().StringVar(&s3Region, "s3-region", "us-east-1", "S3 region")
	rootCmd.PersistentFlags().StringVar(&s3Endpoint, "s3-endpoint", "", "S3 endpoint URL")
	rootCmd.PersistentFlags().StringVar(&s3FileName, "s3-filename", "", "S3 filename")

	// Notification configuration flags
	rootCmd.PersistentFlags().StringVar(&pushoverAPIKey, "pushover-api-key", "", "Pushover API key")
	rootCmd.PersistentFlags().StringVar(&pushoverUserKey, "pushover-user-key", "", "Pushover user key")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".vault-backup" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".vault-backup")
	}

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// Bind flags to viper
	_ = viper.BindPFlags(rootCmd.PersistentFlags())
	bindFlags(rootCmd)

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

// bindFlags binds each cobra flag to its associated viper configuration
func bindFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && viper.IsSet(f.Name) {
			val := viper.Get(f.Name)
			cmd.PersistentFlags().Set(f.Name, fmt.Sprintf("%v", val))
		}
	})
}
