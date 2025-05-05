package notify

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
)

type NotificationType string

const (
	NotificationTypeBackup  NotificationType = "Backup"
	NotificationTypeRestore NotificationType = "Restoration"
)

type NotificationStatus struct {
	Success    bool
	Duration   time.Duration
	SizeBytes  int64
	Error      error
	Type       NotificationType
	Additional map[string]string
}

type Config struct {
	APIKey  string
	UserKey string
}

type Client struct {
	config *Config
}

func NewClient(config *Config) *Client {
	if config == nil {
		return nil
	}
	return &Client{
		config: config,
	}
}

func (c *Client) Notify(ctx context.Context, status NotificationStatus) error {
	if !isValidPushoverToken(c.config.APIKey) || !isValidPushoverUser(c.config.UserKey) {
		return fmt.Errorf("invalid pushover credentials")
	}

	message := &bytes.Buffer{}
	statusEmoji := map[bool]string{true: "✅ Success", false: "❌ Failed"}[status.Success]
	fmt.Fprintf(message, "• Status: %s\n", statusEmoji)
	fmt.Fprintf(message, "• Type: %s\n", status.Type)
	fmt.Fprintf(message, "• Duration: %s\n", status.Duration.Round(time.Second))

	if status.Success {
		if status.SizeBytes > 0 {
			fmt.Fprintf(message, "• Size: %s\n", humanize.Bytes(uint64(status.SizeBytes)))
		}
	} else if status.Error != nil {
		formattedError := strings.ReplaceAll(status.Error.Error(), ": ", "\n• ")
		fmt.Fprintf(message, "• <b>Failure Reason:</b>\n<pre>%s</pre>", formattedError)
	}

	for key, value := range status.Additional {
		fmt.Fprintf(message, "• %s: %s\n", key, value)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	fields := map[string]string{
		"token":   c.config.APIKey,
		"user":    c.config.UserKey,
		"title":   fmt.Sprintf("Vault %s Report", status.Type),
		"message": message.String(),
		"html":    "1",
		"priority": map[bool]string{
			true:  "0",
			false: "1",
		}[status.Success],
	}

	for field, value := range fields {
		if err := writeField(writer, field, value); err != nil {
			return err
		}
	}

	if err := writer.Close(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST",
		"https://api.pushover.net/1/messages.json", body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("Warning: failed to close response body: %v\n", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pushover API error (HTTP %d): %s",
			resp.StatusCode,
			strings.TrimSpace(string(respBody)))
	}

	return nil
}

func isValidPushoverToken(token string) bool {
	clean := strings.TrimSpace(token)
	return len(clean) == 30 && strings.HasPrefix(clean, "a")
}

func isValidPushoverUser(userKey string) bool {
	clean := strings.TrimSpace(userKey)
	return len(clean) == 30 && strings.HasPrefix(clean, "u")
}

func writeField(writer *multipart.Writer, fieldname, value string) error {
	if err := writer.WriteField(fieldname, value); err != nil {
		return fmt.Errorf("failed to write %s field: %w", fieldname, err)
	}
	return nil
}
