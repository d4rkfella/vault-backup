package retry

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog/log"
)

// Config holds configuration parameters for the retry mechanism.
type Config struct {
	MaxAttempts  int
	InitialDelay time.Duration
	MaxDelay     time.Duration // Optional: Cap the delay between retries
}

// IsRetryableFunc defines the signature for functions that check if an error is transient.
type IsRetryableFunc func(err error) bool

// OperationFunc defines the signature for the function to be executed and potentially retried.
type OperationFunc func(ctx context.Context) error

// ExecuteWithRetry attempts to execute the operation, retrying with exponential backoff
// if the operation fails with a retryable error.
func ExecuteWithRetry(ctx context.Context, cfg Config, operation OperationFunc, isRetryable IsRetryableFunc, operationName string) error {
	if cfg.MaxAttempts <= 0 {
		return errors.New("MaxAttempts must be greater than 0")
	}

	if operation == nil {
		return errors.New("nil operation")
	}

	currentDelay := cfg.InitialDelay
	var lastErr error

	log.Trace().Str("operation", operationName).Msg("Starting operation with retry")

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		// Check context before attempting the operation
		select {
		case <-ctx.Done():
			log.Warn().Str("operation", operationName).Int("attempt", attempt).Msg("Context cancelled before executing operation attempt")
			if lastErr != nil {
				// Return the last known error if context is cancelled during backoff/wait
				return lastErr // Or potentially wrap with context.Canceled?
			}
			return ctx.Err() // Return context error if cancelled before first attempt or between attempts without prior error
		default:
			// Context is not cancelled, proceed
		}

		log.Trace().Str("operation", operationName).Int("attempt", attempt).Int("max_attempts", cfg.MaxAttempts).Msg("Executing operation attempt")
		lastErr = operation(ctx) // Execute the actual function

		if lastErr == nil {
			log.Trace().Str("operation", operationName).Int("attempt", attempt).Msg("Operation successful")
			return nil // Success
		}

		log.Warn().Err(lastErr).Str("operation", operationName).Int("attempt", attempt).Int("max_attempts", cfg.MaxAttempts).Msg("Operation attempt failed")

		// Check if the error is retryable and if we haven't reached max attempts
		if !isRetryable(lastErr) || attempt == cfg.MaxAttempts {
			log.Error().Err(lastErr).Str("operation", operationName).Int("attempt", attempt).Bool("retryable", isRetryable(lastErr)).Msg("Permanent error or max attempts reached, stopping retries.")
			return lastErr // Return the last error (permanent or final attempt failed)
		}

		// Calculate delay for next retry
		delay := currentDelay
		log.Warn().Err(lastErr).Str("operation", operationName).Int("attempt", attempt).Dur("retry_after", delay).Msg("Transient error encountered, scheduling retry.")

		// Wait for the delay or context cancellation
		select {
		case <-time.After(delay):
			// Increase delay for the next attempt (exponential backoff)
			currentDelay *= 2
			// Cap the delay if MaxDelay is set
			if cfg.MaxDelay > 0 && currentDelay > cfg.MaxDelay {
				currentDelay = cfg.MaxDelay
			}
		case <-ctx.Done():
			log.Warn().Err(ctx.Err()).Str("operation", operationName).Int("attempt", attempt).Msg("Context cancelled during retry delay")
			return lastErr // Return the last operational error, not the context cancellation error
		}
	}

	// Should theoretically not be reached if MaxAttempts >= 1, but return last error just in case
	log.Error().Err(lastErr).Str("operation", operationName).Msg("Exited retry loop unexpectedly")
	return lastErr
}
