package retry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Test helper functions
type mockOperation struct {
	attempts     int
	successAfter int
	err          error
}

func (m *mockOperation) execute(ctx context.Context) error {
	m.attempts++
	if m.attempts >= m.successAfter {
		return nil
	}
	return m.err
}

func TestExecuteWithRetry_Success(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		MaxAttempts:  3,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
	}

	// Test immediate success
	t.Run("immediate success", func(t *testing.T) {
		op := &mockOperation{successAfter: 1}
		err := ExecuteWithRetry(ctx, cfg, op.execute, func(err error) bool { return true }, "test")
		assert.NoError(t, err)
		assert.Equal(t, 1, op.attempts)
	})

	// Test success after retry
	t.Run("success after retry", func(t *testing.T) {
		op := &mockOperation{
			successAfter: 2,
			err:          errors.New("transient error"),
		}
		err := ExecuteWithRetry(ctx, cfg, op.execute, func(err error) bool { return true }, "test")
		assert.NoError(t, err)
		assert.Equal(t, 2, op.attempts)
	})
}

func TestExecuteWithRetry_PermanentError(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		MaxAttempts:  3,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
	}

	permanentErr := errors.New("permanent error")
	op := &mockOperation{
		successAfter: 999, // Never succeed
		err:          permanentErr,
	}

	err := ExecuteWithRetry(ctx, cfg, op.execute, func(err error) bool { return false }, "test")
	assert.Error(t, err)
	assert.Equal(t, permanentErr, err)
	assert.Equal(t, 1, op.attempts, "Should not retry permanent errors")
}

func TestExecuteWithRetry_MaxAttempts(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		MaxAttempts:  2,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
	}

	transientErr := errors.New("transient error")
	op := &mockOperation{
		successAfter: 999, // Never succeed
		err:          transientErr,
	}

	err := ExecuteWithRetry(ctx, cfg, op.execute, func(err error) bool { return true }, "test")
	assert.Error(t, err)
	assert.Equal(t, transientErr, err)
	assert.Equal(t, 2, op.attempts, "Should retry exactly MaxAttempts times")
}

func TestExecuteWithRetry_ContextCancellation(t *testing.T) {
	cfg := Config{
		MaxAttempts:  3,
		InitialDelay: 100 * time.Millisecond,
		MaxDelay:     200 * time.Millisecond,
	}

	// Test cancellation before first attempt
	t.Run("cancel before first attempt", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		op := &mockOperation{successAfter: 1}
		err := ExecuteWithRetry(ctx, cfg, op.execute, func(err error) bool { return true }, "test")
		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
		assert.Equal(t, 0, op.attempts)
	})

	// Test cancellation during retry delay
	t.Run("cancel during retry delay", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		transientErr := errors.New("transient error")
		op := &mockOperation{
			successAfter: 999, // Never succeed
			err:          transientErr,
		}

		// Cancel after a short delay
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		err := ExecuteWithRetry(ctx, cfg, op.execute, func(err error) bool { return true }, "test")
		assert.Error(t, err)
		assert.Equal(t, transientErr, err, "Should return the last operational error")
		assert.Equal(t, 1, op.attempts)
	})
}

func TestExecuteWithRetry_DelayCapping(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		MaxAttempts:  4,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     30 * time.Millisecond,
	}

	transientErr := errors.New("transient error")
	op := &mockOperation{
		successAfter: 999, // Never succeed
		err:          transientErr,
	}

	start := time.Now()
	err := ExecuteWithRetry(ctx, cfg, op.execute, func(err error) bool { return true }, "test")
	duration := time.Since(start)

	assert.Error(t, err)
	assert.Equal(t, transientErr, err)
	assert.Equal(t, 4, op.attempts)

	// Verify that delays were capped
	// Initial: 10ms, 2nd: 20ms, 3rd: 30ms (capped), 4th: 30ms (capped)
	// Total should be less than 100ms (allowing for some overhead)
	assert.Less(t, duration, 100*time.Millisecond)
}

func TestExecuteWithRetry_ZeroMaxAttempts(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		MaxAttempts:  0,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
	}

	op := &mockOperation{successAfter: 1}
	err := ExecuteWithRetry(ctx, cfg, op.execute, func(err error) bool { return true }, "test")
	assert.Error(t, err)
	assert.Equal(t, 0, op.attempts, "Should not attempt operation with MaxAttempts=0")
}

func TestExecuteWithRetry_NilOperation(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		MaxAttempts:  3,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
	}

	err := ExecuteWithRetry(ctx, cfg, nil, func(err error) bool { return true }, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil operation")
}
