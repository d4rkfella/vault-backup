package pushover

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gregdel/pushover"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockPushoverAPI struct {
	mock.Mock
}

func (m *mockPushoverAPI) SendMessage(message *pushover.Message, recipient *pushover.Recipient) (*pushover.Response, error) {
	args := m.Called(message, recipient)
	response, _ := args.Get(0).(*pushover.Response)
	return response, args.Error(1)
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{"Zero", 0, "0 B"},
		{"Bytes", 500, "500 B"},
		{"KiB", 1536, "1.5 KiB"},
		{"MiB", 1572864, "1.5 MiB"},
		{"GiB", 1610612736, "1.5 GiB"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, formatBytes(tc.bytes))
		})
	}
}

func TestNotify_Success(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockPushoverAPI)
	cfg := &Config{APIKey: "fakeAPI", UserKey: "fakeUser"}
	client := &Client{
		app: mockAPI,
		cfg: cfg,
	}

	opType := "backup"
	duration := 15 * time.Second
	sizeBytes := int64(2048)
	details := map[string]string{
		"File":     "backup-file.snap",
		"ExtraKey": "ExtraValue",
	}

	expectedTitle := fmt.Sprintf("✅ Vault %s Successful", opType)
	expectedMsgPrefix := fmt.Sprintf(
		"Operation: %s\nFile: %s\nDuration: %s\nSize: %s",
		opType,
		details["File"],
		duration.Round(time.Second).String(),
		formatBytes(sizeBytes),
	)
	expectedMsgSuffix := fmt.Sprintf("\n\nDetails:\n%s: %s", "ExtraKey", details["ExtraKey"])
	expectedPriority := pushover.PriorityNormal

	mockAPI.On("SendMessage",
		mock.MatchedBy(func(msg *pushover.Message) bool {
			assert.Equal(t, expectedTitle, msg.Title)
			assert.Contains(t, msg.Message, expectedMsgPrefix)
			assert.Contains(t, msg.Message, expectedMsgSuffix)
			assert.Equal(t, expectedPriority, msg.Priority)
			assert.NotZero(t, msg.Timestamp)
			return true
		}),
		mock.AnythingOfType("*pushover.Recipient"),
	).Return(&pushover.Response{Status: 1}, nil).Once()

	err := client.Notify(ctx, true, opType, duration, sizeBytes, nil, details)

	require.NoError(t, err)
	mockAPI.AssertExpectations(t)
}

func TestNotify_Failure(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockPushoverAPI)
	cfg := &Config{APIKey: "fakeAPI", UserKey: "fakeUser"}
	client := &Client{
		app: mockAPI,
		cfg: cfg,
	}

	opType := "restore"
	duration := 5 * time.Second
	notifyErr := errors.New("vault restore failed")
	details := map[string]string{
		"File": "backup-restore-fail.snap",
	}

	expectedTitle := fmt.Sprintf("❌ Vault %s Failed", opType)
	expectedMsgPrefix := fmt.Sprintf(
		"Operation: %s\nFile: %s\nDuration: %s\nError: %v",
		opType,
		details["File"],
		duration.Round(time.Second).String(),
		notifyErr,
	)
	expectedPriority := pushover.PriorityHigh

	mockAPI.On("SendMessage",
		mock.MatchedBy(func(msg *pushover.Message) bool {
			assert.Equal(t, expectedTitle, msg.Title)
			assert.Contains(t, msg.Message, expectedMsgPrefix)
			assert.NotContains(t, msg.Message, "\n\nDetails:")
			assert.Equal(t, expectedPriority, msg.Priority)
			assert.NotZero(t, msg.Timestamp)
			return true
		}),
		mock.AnythingOfType("*pushover.Recipient"),
	).Return(&pushover.Response{Status: 1}, nil).Once()

	err := client.Notify(ctx, false, opType, duration, 0, notifyErr, details)

	require.NoError(t, err)
	mockAPI.AssertExpectations(t)
}

func TestNotify_SendError(t *testing.T) {
	ctx := context.Background()
	mockAPI := new(mockPushoverAPI)
	cfg := &Config{APIKey: "fakeAPI", UserKey: "fakeUser"}
	client := &Client{
		app: mockAPI,
		cfg: cfg,
	}

	expectedError := errors.New("pushover API error")

	mockAPI.On("SendMessage",
		mock.AnythingOfType("*pushover.Message"),
		mock.AnythingOfType("*pushover.Recipient"),
	).Return(nil, expectedError).Once()

	err := client.Notify(ctx, true, "backup", 0, 0, nil, nil)

	require.Error(t, err)
	assert.ErrorContains(t, err, expectedError.Error())
	mockAPI.AssertExpectations(t)
}

func TestNewClient(t *testing.T) {
	cfg := &Config{
		APIKey:  "test-api-key",
		UserKey: "test-user-key",
	}

	client := NewClient(cfg)

	require.NotNil(t, client, "NewClient returned nil")
	assert.NotNil(t, client.app, "Client app field is nil")
	assert.Equal(t, cfg, client.cfg, "Client config field does not match input")

}
