package notification

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"regexp"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/rs/zerolog/log"

	"github.com/d4rkfella/vault-backup/internal/util"  // For RedactKey
	"github.com/d4rkfella/vault-backup/internal/vault" // For SecureString
)

// pushoverURL is the endpoint for the Pushover API v1.
var pushoverURL = "https://api.pushover.net/1/messages.json"

var (
	// validPushoverToken is a regex to validate the format of Pushover API tokens.
	validPushoverToken = regexp.MustCompile(`^[a-zA-Z0-9]{30}$`)
	// validPushoverUser is a regex to validate the format of Pushover user/group keys.
	validPushoverUser = regexp.MustCompile(`^[a-zA-Z0-9]{30}$`)
)

// SendPushoverNotification sends a formatted status notification (success or failure)
// via the Pushover API using the provided credentials and backup details.
// It skips sending if credentials are missing or invalid.
func SendPushoverNotification(
	apiKey, userKey vault.SecureString, // API token and user/group key.
	success bool, // Whether the backup operation succeeded.
	duration time.Duration, // Duration of the backup operation.
	snapshotSize int64, // Size of the created snapshot in bytes.
	runErr error, // The error encountered, if success is false.
) error {
	apiKeyStr := apiKey.String() // Get string value; Zero() is handled by the caller (run func).
	userKeyStr := userKey.String()

	// Skip if credentials are not valid.
	if !isValidPushoverToken(apiKeyStr) || !isValidPushoverUser(userKeyStr) {
		log.Warn().Str("component", "notification").Msg("Invalid or missing Pushover credentials, skipping notification")
		return nil // Not an application error if not configured.
	}

	log.Debug().Str("component", "notification").Msg("Preparing Pushover notification")

	// Prepare message title, body, priority, and sound based on success status.
	title := "Vault Backup Success"
	priority := "0"     // Normal priority
	sound := "pushover" // Default sound
	message := fmt.Sprintf("Backup completed successfully.\nDuration: %s\nSize: %s",
		duration.Round(time.Second), humanize.Bytes(uint64(snapshotSize)))

	if !success {
		title = "Vault Backup FAILED"
		priority = "1"  // High priority
		sound = "siren" // Failure sound
		errMsg := "Unknown error"
		if runErr != nil {
			errMsg = runErr.Error()
		}
		message = fmt.Sprintf("Backup failed!\nDuration: %s\nError: %s",
			duration.Round(time.Second), errMsg)
	}

	// Build the multipart HTTP request body.
	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)
	// Write fields (ignore errors as WriteField returns the writer error on Close).
	_ = writer.WriteField("token", apiKeyStr)
	_ = writer.WriteField("user", userKeyStr)
	_ = writer.WriteField("title", title)
	_ = writer.WriteField("message", message)
	_ = writer.WriteField("priority", priority)
	_ = writer.WriteField("sound", sound)

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to build pushover request body: %w", err)
	}

	// Create the HTTP request (consider adding context propagation here).
	req, err := http.NewRequest("POST", pushoverURL, &requestBody)
	if err != nil {
		return fmt.Errorf("failed to create pushover request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Log request details (with redacted credentials).
	log.Debug().Str("component", "notification").
		Str("user", util.RedactKey(userKeyStr)).
		Str("token", util.RedactKey(apiKeyStr)).
		Str("priority", priority).
		Str("sound", sound).
		Str("title", title).
		Int("message_len", len(message)).
		Msg("Sending Pushover request")

	// Send the request using a client with a timeout.
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("pushover request failed: %w", err)
	}
	// Ensure response body is closed and check error.
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn().Err(err).Msg("Failed to close Pushover response body")
		}
	}()

	// Check response status code.
	bodyBytes, _ := io.ReadAll(resp.Body) // Read body for potential error messages.
	if resp.StatusCode != http.StatusOK {
		log.Error().Str("component", "notification").Int("status_code", resp.StatusCode).Str("response", string(bodyBytes)).Msg("Pushover API returned error")
		return fmt.Errorf("pushover API error: status %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	log.Info().Str("component", "notification").Msg("Pushover notification sent successfully")
	return nil
}

// isValidPushoverToken checks if a string looks like a valid Pushover API token (30 alphanumeric chars).
func isValidPushoverToken(token string) bool {
	return validPushoverToken.MatchString(token)
}

// isValidPushoverUser checks if a string looks like a valid Pushover user/group key (30 alphanumeric chars).
func isValidPushoverUser(userKey string) bool {
	return validPushoverUser.MatchString(userKey)
}
