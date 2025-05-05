package pushover

import (
	"context"
	"fmt"
	"strings"
	"time"

	pushover "github.com/gregdel/pushover"
)

type Config struct {
	APIKey  string
	UserKey string
}

type pushoverAPI interface {
	SendMessage(message *pushover.Message, recipient *pushover.Recipient) (*pushover.Response, error)
}

type Client struct {
	app pushoverAPI
	cfg *Config
}

func NewClient(config *Config) *Client {
	pushoverApp := pushover.New(config.APIKey)
	return &Client{
		app: pushoverApp,
		cfg: config,
	}
}

func (c *Client) Notify(_ context.Context, success bool, opType string, duration time.Duration, sizeBytes int64, notifyErr error, details map[string]string) error {
	recipient := pushover.NewRecipient(c.cfg.UserKey)

	var title, message string
	priority := pushover.PriorityNormal
	file := details["File"]

	if success {
		title = fmt.Sprintf("✅ Vault %s Successful", opType)
		message = fmt.Sprintf(
			"Operation: %s\nFile: %s\nDuration: %s\nSize: %s",
			opType,
			file,
			duration.Round(time.Second).String(),
			formatBytes(sizeBytes),
		)
	} else {
		title = fmt.Sprintf("❌ Vault %s Failed", opType)
		message = fmt.Sprintf(
			"Operation: %s\nFile: %s\nDuration: %s\nError: %v",
			opType,
			file,
			duration.Round(time.Second).String(),
			notifyErr,
		)
		priority = pushover.PriorityHigh
	}

	var additionalDetails []string
	for k, v := range details {
		if k != "File" {
			additionalDetails = append(additionalDetails, fmt.Sprintf("%s: %s", k, v))
		}
	}
	if len(additionalDetails) > 0 {
		message += "\n\nDetails:\n" + strings.Join(additionalDetails, "\n")
	}

	msg := &pushover.Message{
		Title:     title,
		Message:   message,
		Priority:  priority,
		Timestamp: time.Now().Unix(),
	}

	_, err := c.app.SendMessage(msg, recipient)
	if err != nil {
		return fmt.Errorf("failed to send pushover notification: %w", err)
	}
	return nil
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}
