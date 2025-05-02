package logging

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Init sets up the global zerolog logger based on the provided level string.
func Init(levelString string) {
	// Default to info level
	logLevel := zerolog.InfoLevel
	parsedLevel, err := zerolog.ParseLevel(levelString)
	if err != nil {
		// Use the default logger for this initial warning before full setup
		log.Warn().Str("provided_level", levelString).Err(err).Msg("Invalid LOG_LEVEL, defaulting to 'info'")
	} else if parsedLevel != zerolog.NoLevel { // Only update if parsing succeeded AND level is not NoLevel
		logLevel = parsedLevel
	} else {
		// Handle cases where ParseLevel returns NoLevel without error (e.g., empty string)
		// We already defaulted logLevel to InfoLevel, so no action needed here, but could log if desired.
		log.Debug().Str("provided_level", levelString).Msg("Empty or NoLevel provided, using default InfoLevel")
	}
	zerolog.SetGlobalLevel(logLevel)

	// Configure console writer
	// Pretty print for debug/trace, simpler for others
	if logLevel <= zerolog.DebugLevel {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
			With().Str("service", "vault-backup").Logger() // Add service field
	} else {
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			NoColor:    true, // Assume non-interactive for higher levels
			TimeFormat: time.RFC3339,
		}).With().Str("service", "vault-backup").Logger() // Add service field
	}

	// Use the newly configured logger for the final confirmation message
	log.Info().Str("log_level", logLevel.String()).Msg("Logger initialized")
}
