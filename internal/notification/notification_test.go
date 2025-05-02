package notification

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/d4rkfella/vault-backup/internal/vault"
)

func TestIsValidPushoverToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{"ValidToken", "abcdefghij1234567890abcdefghij", true},
		{"InvalidLength", "abcdefghij1234567890", false},
		{"InvalidChars", "abcdefghij!@#$%^&*()abcdefghij", false},
		{"EmptyToken", "", false},
		{"TooLong", "abcdefghij1234567890abcdefghij123", false},
		{"AllNumbers", "123456789012345678901234567890", true},
		{"AllLetters", "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD", true},
		{"MixedCase", "abcDEFghij1234567890abcDEFghij", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidPushoverToken(tt.token)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidPushoverUser(t *testing.T) {
	tests := []struct {
		name     string
		userKey  string
		expected bool
	}{
		{"ValidUser", "abcdefghij1234567890abcdefghij", true},
		{"InvalidLength", "abcdefghij1234567890", false},
		{"InvalidChars", "abcdefghij!@#$%^&*()abcdefghij", false},
		{"EmptyUser", "", false},
		{"TooLong", "abcdefghij1234567890abcdefghij123", false},
		{"AllNumbers", "123456789012345678901234567890", true},
		{"AllLetters", "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD", true},
		{"MixedCase", "abcDEFghij1234567890abcDEFghij", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidPushoverUser(tt.userKey)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSendPushoverNotification(t *testing.T) {
	validToken := "abcdefghij1234567890abcdefghij"
	validUser := "abcdefghij1234567890abcdefghij"
	invalidToken := "invalid"
	invalidUser := "invalid"

	tests := []struct {
		name         string
		apiKey       vault.SecureString
		userKey      vault.SecureString
		success      bool
		duration     time.Duration
		snapshotSize int64
		runErr       error
		mockStatus   int
		mockResponse string
		expectError  bool
		expectBody   []string // Substrings that should be in the request body
	}{
		{
			name:         "SuccessfulNotification",
			apiKey:       vault.NewSecureString([]byte(validToken)),
			userKey:      vault.NewSecureString([]byte(validUser)),
			success:      true,
			duration:     5 * time.Minute,
			snapshotSize: 1024 * 1024 * 100, // 100MB
			runErr:       nil,
			mockStatus:   http.StatusOK,
			mockResponse: `{"status":1}`,
			expectError:  false,
			expectBody:   []string{"Vault Backup Success", "105 MB", "5m0s"},
		},
		{
			name:         "FailureNotification",
			apiKey:       vault.NewSecureString([]byte(validToken)),
			userKey:      vault.NewSecureString([]byte(validUser)),
			success:      false,
			duration:     1 * time.Minute,
			snapshotSize: 0,
			runErr:       errors.New("backup failed"),
			mockStatus:   http.StatusOK,
			mockResponse: `{"status":1}`,
			expectError:  false,
			expectBody:   []string{"Vault Backup FAILED", "backup failed", "1m0s"},
		},
		{
			name:         "InvalidCredentials",
			apiKey:       vault.NewSecureString([]byte(invalidToken)),
			userKey:      vault.NewSecureString([]byte(invalidUser)),
			success:      true,
			duration:     time.Minute,
			snapshotSize: 1024,
			runErr:       nil,
			mockStatus:   http.StatusOK,
			mockResponse: `{"status":1}`,
			expectError:  false, // Should skip silently
			expectBody:   nil,
		},
		{
			name:         "APIError",
			apiKey:       vault.NewSecureString([]byte(validToken)),
			userKey:      vault.NewSecureString([]byte(validUser)),
			success:      true,
			duration:     time.Minute,
			snapshotSize: 1024,
			runErr:       nil,
			mockStatus:   http.StatusUnauthorized,
			mockResponse: `{"status":0,"error":"invalid token"}`,
			expectError:  true,
			expectBody:   []string{"Vault Backup Success"},
		},
		{
			name:         "UnknownError",
			apiKey:       vault.NewSecureString([]byte(validToken)),
			userKey:      vault.NewSecureString([]byte(validUser)),
			success:      false,
			duration:     time.Minute,
			snapshotSize: 1024,
			runErr:       nil,
			mockStatus:   http.StatusOK,
			mockResponse: `{"status":1}`,
			expectError:  false,
			expectBody:   []string{"Unknown error"},
		},
		{
			name:         "NetworkError",
			apiKey:       vault.NewSecureString([]byte(validToken)),
			userKey:      vault.NewSecureString([]byte(validUser)),
			success:      true,
			duration:     time.Minute,
			snapshotSize: 1024,
			runErr:       nil,
			mockStatus:   http.StatusOK,
			mockResponse: `{"status":1}`,
			expectError:  true,
			expectBody:   []string{"Vault Backup Success"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test server to mock Pushover API
			var server *httptest.Server
			if tt.name == "NetworkError" {
				// Create a server that immediately closes the connection
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hj, ok := w.(http.Hijacker)
					if !ok {
						t.Fatal("webserver doesn't support hijacking")
					}
					conn, _, err := hj.Hijack()
					if err != nil {
						t.Fatal(err)
					}
					if conn != nil {
						// Simulate sending the response
						_ = conn.Close() // Ignore error in mock server
					}
				}))
			} else {
				server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Check request method
					assert.Equal(t, "POST", r.Method)

					// Check Content-Type header
					contentType := r.Header.Get("Content-Type")
					assert.True(t, strings.HasPrefix(contentType, "multipart/form-data"))

					// Read and verify request body if expected
					if tt.expectBody != nil {
						body, err := io.ReadAll(r.Body)
						require.NoError(t, err)
						bodyStr := string(body)
						for _, expected := range tt.expectBody {
							assert.Contains(t, bodyStr, expected)
						}
					}

					// Send mock response
					w.WriteHeader(tt.mockStatus)
					if tt.mockResponse != "" {
						_, err := fmt.Fprint(w, tt.mockResponse)
						require.NoError(t, err) // Check write error
					}
				}))
			}
			defer server.Close()

			// Override pushoverURL for testing
			originalURL := pushoverURL
			pushoverURL = server.URL
			defer func() { pushoverURL = originalURL }()

			// Call the function
			err := SendPushoverNotification(tt.apiKey, tt.userKey, tt.success, tt.duration, tt.snapshotSize, tt.runErr)

			// Check error
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
