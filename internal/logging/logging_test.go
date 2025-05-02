package logging

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name          string
		inputLevel    string
		expectedLevel zerolog.Level
	}{
		{"Debug Level", "debug", zerolog.DebugLevel},
		{"Info Level", "info", zerolog.InfoLevel},
		{"Warn Level", "warn", zerolog.WarnLevel},
		{"Error Level", "error", zerolog.ErrorLevel},
		{"Fatal Level", "fatal", zerolog.FatalLevel},
		{"Panic Level", "panic", zerolog.PanicLevel},
		{"Trace Level", "trace", zerolog.TraceLevel},
		{"Case Insensitive", "DEBUG", zerolog.DebugLevel},
		{"Empty String", "", zerolog.InfoLevel},          // Defaults to Info
		{"Invalid String", "invalid", zerolog.InfoLevel}, // Defaults to Info
		{"Partial Match", "inf", zerolog.InfoLevel},      // Defaults to Info (ParseLevel is exact)
	}

	// Important: Store original global level to restore after tests
	originalLevel := zerolog.GlobalLevel()
	t.Cleanup(func() {
		zerolog.SetGlobalLevel(originalLevel)
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange & Act
			Init(tt.inputLevel)

			// Assert
			assert.Equal(t, tt.expectedLevel, zerolog.GlobalLevel())
		})
	}
}
