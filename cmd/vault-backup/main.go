package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/KimMachineGun/automemlimit/memlimit"
	"github.com/rs/zerolog/log"
	"go.uber.org/automaxprocs/maxprocs"

	// Internal packages
	"github.com/d4rkfella/vault-backup/internal/config"
	"github.com/d4rkfella/vault-backup/internal/logging"
	"github.com/d4rkfella/vault-backup/internal/notification"
	"github.com/d4rkfella/vault-backup/internal/s3"
	"github.com/d4rkfella/vault-backup/internal/util"
	"github.com/d4rkfella/vault-backup/internal/vault"
)

var (
	// version is set during build time.
	version = "dev"
	// commit is set during build time.
	commit = "none"
)

// Exit Codes defines specific exit codes for different application outcomes.
const (
	// ExitCodeSuccess indicates successful execution.
	ExitCodeSuccess = 0
	// ExitCodeGeneric indicates a generic or unhandled error.
	ExitCodeGeneric = 1
	// ExitCodeConfigError indicates an error during configuration loading.
	ExitCodeConfigError = 2
	// ExitCodeVaultConnection indicates an error connecting to Vault.
	ExitCodeVaultConnection = 3
	// ExitCodeVaultAuth indicates an error authenticating with Vault.
	ExitCodeVaultAuth = 4
	// ExitCodeVaultSecretRead indicates an error reading secrets from Vault.
	ExitCodeVaultSecretRead = 5
	// ExitCodeVaultSnapshot indicates an error creating a Vault snapshot.
	ExitCodeVaultSnapshot = 6
	// ExitCodeS3Session indicates an error creating an S3 session.
	ExitCodeS3Session = 7
	// ExitCodeS3Upload indicates an error uploading the snapshot to S3.
	ExitCodeS3Upload = 8
	// ExitCodeSnapshotFileError indicates an error related to local snapshot file handling.
	ExitCodeSnapshotFileError = 9
)

// main is the application entry point.
// It sets up configuration, logging, signal handling, context, and invokes the core run function.
func main() {
	logging.Init("info")

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("Configuration loading failed")
	}

	// Re-initialize logger with configured level
	logging.Init(cfg.LogLevel)

	setupSystemResources(cfg)

	// Create contexts for signal handling and timeout.
	baseCtx := context.Background()
	signalCtx, stopSignalListener := signal.NotifyContext(baseCtx, syscall.SIGINT, syscall.SIGTERM)
	defer stopSignalListener()
	runCtx, cancelRun := context.WithTimeout(signalCtx, 10*time.Minute) // TODO: Make timeout configurable?
	defer cancelRun()

	// Setup exit code handling, including panic recovery.
	exitCode := ExitCodeSuccess // Default to success
	defer func() {
		if r := recover(); r != nil {
			log.Error().
				Str("stack", string(debug.Stack())).
				Msgf("Unexpected panic: %v", r)
			exitCode = ExitCodeGeneric
		}
		log.Info().Int("exit_code", exitCode).Msg("Application exiting")
		os.Exit(exitCode)
	}()

	// Execute the main application logic.
	exitCode = run(runCtx, cfg)
}

// run orchestrates the main backup process.
// It handles Vault client setup, credential fetching, S3 session creation,
// snapshot creation, snapshot upload, and retention cleanup.
// Returns an exit code based on success or failure type.
func run(ctx context.Context, cfg *config.Config) int {
	startTime := time.Now()
	success := true
	var runErr error // Use a specific variable to store the primary error
	var snapshotSize int64
	var sendPushover bool
	var pushoverAPI, pushoverUser vault.SecureString
	snapshotPath := "" // Initialize snapshot path

	// Defer final status logging and notification.
	defer func() {
		// Handle potential panics within run
		if r := recover(); r != nil {
			success = false
			if runErr == nil {
				runErr = fmt.Errorf("panic: %v", r)
			}
			log.Error().
				Str("stack", string(debug.Stack())).
				Msgf("Recovered panic in run: %v", r)
		}

		duration := time.Since(startTime)

		// Send notification if configured
		if sendPushover {
			if notifyErr := notification.SendPushoverNotification(
				pushoverAPI, // Pass the secure strings
				pushoverUser,
				success,
				duration,
				snapshotSize,
				runErr,
			); notifyErr != nil {
				log.Warn().Err(notifyErr).Msg("Pushover notification failed")
			}
			// Zero out keys after potential use (caller of run should ensure this eventually happens too)
			pushoverAPI.Zero()
			pushoverUser.Zero()
		}

		// Final logging
		if success {
			log.Info().
				Dur("duration", duration).
				Int64("size_bytes", snapshotSize).
				Msg("Backup process finished successfully")
		} else {
			log.Error().
				Err(runErr). // Log the primary error
				Dur("duration", duration).
				Msg("Backup process failed")
			// Optional: Log error chain if needed
			if runErr != nil {
				var errChain []string
				for unwrapped := runErr; unwrapped != nil; unwrapped = errors.Unwrap(unwrapped) {
					errChain = append(errChain, unwrapped.Error())
				}
				log.Debug().Strs("error_chain", errChain).Msg("Error details")
			}
		}
	}() // End of deferred function

	// --- Main Backup Logic ---

	log.Debug().Str("component", "vault").Msg("Initializing Vault client")
	// Create a new vault client with the config
	vaultClient, err := vault.NewClient(cfg, nil) // Pass nil to use the real Vault API client
	if err != nil {
		runErr = fmt.Errorf("vault client creation failed: %w", err)
		success = false
		return ExitCodeVaultConnection // Defaulting to connection error for now
	}
	// Then call Login
	if err = vaultClient.Login(ctx); err != nil {
		runErr = fmt.Errorf("vault client login failed: %w", err)
		success = false
		// Attempt to determine specific error type from vault login
		if strings.Contains(err.Error(), "authentication/validation failed") {
			return ExitCodeVaultAuth
		}
		return ExitCodeVaultConnection // Default to connection if auth check fails
	}
	defer vaultClient.Close(ctx) // Ensure client token is revoked

	log.Info().Str("component", "credentials").Msg("Fetching credentials from Vault")
	// Call GetCredentials on the initialized and logged-in client
	creds, err := vaultClient.GetCredentials(ctx)
	if err != nil {
		runErr = fmt.Errorf("fetching credentials failed: %w", err)
		success = false
		return ExitCodeVaultSecretRead
	}
	defer creds.Zero() // Ensure fetched credentials are zeroed

	// Keep copies of credentials needed later, original creds struct will be zeroed by defer
	if len(creds.PushoverAPI) > 0 && len(creds.PushoverUser) > 0 {
		pushoverAPI = vault.NewSecureString(creds.PushoverAPI.Bytes())   // Clone needed value
		pushoverUser = vault.NewSecureString(creds.PushoverUser.Bytes()) // Clone needed value
		sendPushover = true
		log.Debug().Msg("Pushover credentials found")
	}
	awsAccess := vault.NewSecureString(creds.AWSAccess.Bytes()) // Clone needed value
	awsSecret := vault.NewSecureString(creds.AWSSecret.Bytes()) // Clone needed value
	defer awsAccess.Zero()                                      // Ensure cloned credentials are zeroed
	defer awsSecret.Zero()

	// Create AWS S3 Client
	log.Debug().Str("component", "s3").Msg("Initializing S3 client")
	s3Client, err := s3.NewClient(ctx, cfg, awsAccess, awsSecret)
	if err != nil {
		runErr = fmt.Errorf("s3 client creation failed: %w", err)
		success = false
		return ExitCodeS3Session
	}

	log.Info().Str("component", "backup").Msg("Starting Vault snapshot creation")
	// Call CreateSnapshot on the vaultClient
	snapshotPath, err = vaultClient.CreateSnapshot(ctx)
	if err != nil {
		runErr = fmt.Errorf("snapshot creation failed: %w", err)
		success = false
		// Determine if Vault API error or local file error?
		// Let's check if the error is from os package for file errors
		if _, ok := err.(*os.PathError); ok || errors.Is(err, os.ErrPermission) {
			return ExitCodeSnapshotFileError
		}
		return ExitCodeVaultSnapshot // Assume Vault API error otherwise
	}

	// Get snapshot size if creation succeeded
	fileInfo, statErr := os.Stat(snapshotPath)
	if statErr != nil {
		// Log the error but maybe don't fail the whole backup yet?
		// Or treat it as a fatal error for the snapshot file?
		log.Error().Err(statErr).Str("path", util.SanitizePath(snapshotPath)).Msg("Failed to stat created snapshot file - potential issue")
		// Let's consider this a snapshot file error, as we can't confirm size
		runErr = fmt.Errorf("snapshot file stat failed: %w", statErr)
		success = false
		return ExitCodeSnapshotFileError
	} else {
		snapshotSize = fileInfo.Size()
		log.Debug().Int64("size", snapshotSize).Msg("Snapshot file size determined")
	}

	// Defer snapshot cleanup regardless of creation success (handles partial files)
	// Note: We copy snapshotPath to the closure to avoid issues if it's reassigned.
	// Also copy the relevant config field for the closure
	secureDeleteFlag := cfg.SecureDelete
	defer func() {
		if snapshotPath != "" {
			log.Debug().Str("path", util.SanitizePath(snapshotPath)).Msg("Cleaning up local snapshot file")
			util.SecureDelete(snapshotPath, secureDeleteFlag)
			// Note: We don't change exit code if secure delete fails, just log.
		}
	}()

	// Exit run if snapshot creation failed
	if !success {
		return ExitCodeGeneric
	}

	log.Info().Str("component", "s3").Msg("Uploading snapshot to S3")
	// Call Upload method on the s3Client
	err = s3Client.Upload(ctx, snapshotPath)
	if err != nil {
		runErr = fmt.Errorf("s3 upload failed: %w", err)
		success = false
		return ExitCodeS3Upload
	}

	log.Info().Str("component", "retention").Msg("Cleaning up old snapshots in S3")
	// Call CleanupOldSnapshots method on the s3Client
	err = s3Client.DeleteOldSnapshotsFromS3(ctx)
	if err != nil {
		// Log retention errors but don't mark the entire backup as failed
		log.Warn().Err(err).Msg("S3 cleanup finished with errors")
		if runErr == nil { // Don't overwrite a more critical earlier error
			runErr = fmt.Errorf("retention cleanup failed: %w", err)
		}
	} else {
		log.Info().Msg("S3 cleanup finished")
	}

	// --- End of Main Backup Logic ---

	if !success {
		// This path should technically not be reached if errors are returned correctly above
		// But as a fallback, return generic error code.
		if runErr == nil {
			runErr = errors.New("backup failed for an unknown reason")
		}
		return ExitCodeGeneric
	}
	return ExitCodeSuccess
}

// setupSystemResources configures GOMEMLIMIT and GOMAXPROCS based on available resources.
func setupSystemResources(cfg *config.Config) {
	// Set GOMEMLIMIT using automemlimit
	undo, err := memlimit.SetGoMemLimitWithOpts(
		memlimit.WithRatio(cfg.MemoryLimitRatio),
		// memlimit.WithProvider(memlimit.ApplyPolicy), // Rely on default provider
		// memlimit.WithLogger(log.With().Str("component", "memlimit").Logger()), // Remove logger for now
	)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to set GOMEMLIMIT automatically")
	} else {
		log.Info().Float64("ratio", cfg.MemoryLimitRatio).Msg("Automatic GOMEMLIMIT activated")
		_ = undo
	}

	// Set GOMAXPROCS using automaxprocs
	_, err = maxprocs.Set(
		maxprocs.Logger(func(s string, i ...interface{}) { log.Info().Msgf(s, i...) }),
	)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to set GOMAXPROCS automatically")
	}
	log.Info().Str("component", "system").Int("gomaxprocs", runtime.GOMAXPROCS(0)).Msg("System resources configured")
	log.Info().Str("component", "system").Str("version", version).Str("commit", commit).Msg("Application starting")
}
