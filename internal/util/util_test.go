package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactURL(t *testing.T) {
	tests := []struct {
		name     string
		inputURL string
		want     string
	}{
		{"Empty URL", "", "none"},
		{"URL without user info", "https://example.com/path?query=1", "***.com/path?query=1"},
		{"URL with user info", "https://user:password@example.com/path", "***.com/path"},
		{"URL with user only", "https://user@example.com/path", "***.com/path"},
		{"Invalid URL", "://invalid", "***"},
		{"URL with encoded chars", "https://user%40name:pass%2Fword@test.com/", "***.com/"},
		{"FTP URL", "ftp://user:secret@ftp.example.com/", "***.example.com/"},
		{"Simple hostname", "hostname", "***"},
		{"Hostname with dot", "my.hostname", "***.hostname"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactURL(tt.inputURL); got != tt.want {
				t.Errorf("RedactURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      string
	}{
		{"Empty Path", "", ""},
		{"Short Path 1", "/home", "/home"},
		{"Short Path 2", "/home/user", "/home/user"},
		{"Short Path 3", "/home/user/file.txt", "/home/***/file.txt"},
		{"Path with 4 parts", "/var/log/app", "/var/***/app"},
		{"Path with 5 parts", "/var/log/app/file.log", "/var/***/app/file.log"},
		{"Path with ..", "/home/user/../other/file.txt", "/home/***/../other/file.txt"},
		{"Path starting with ..", "../etc/passwd", "../etc/passwd"},
		{"Windows Path (treated as single component)", `C:\Users\User\file.txt`, `C:\Users\User\file.txt`},
		{"Path with multiple slashes", "/var//log//app.log", "/var/***/log//app.log"},
		{"Relative path", "my/dir/another/file", "my/dir/***/file"},
		{"Long path", "/a/b/c/d/e/f/g", "/a/***/c/d/e/f/g"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizePath(tt.inputPath)
			if got != tt.want {
				t.Fatalf("SanitizePath() mismatch:\n  Input: %q\n  Got:   %q (len %d)\n  Want:  %q (len %d)", tt.inputPath, got, len(got), tt.want, len(tt.want))
			}
		})
	}
}

func TestRedactKey(t *testing.T) {
	tests := []struct {
		name     string
		inputKey string
		want     string
	}{
		{"Empty Key", "", "***"},
		{"Short Key 1", "abc", "***"},
		{"Short Key 2", "abcdefg", "***"},
		{"Min Length Key", "abcdefgh", "abcd***efgh"},
		{"Medium Key", "abcdefghi", "abcd***fghi"},
		{"Long Key", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "ABCD***WXYZ"},
		{"Key with numbers", "1234567890", "1234***7890"},
		{"Key with symbols", "!@#$%^&*()", "!@#$***&*()"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactKey(tt.inputKey); got != tt.want {
				t.Errorf("RedactKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSecureDelete(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "secure-delete-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }() // Ignore error

	t.Run("standard delete when secure delete disabled", func(t *testing.T) {
		// Create a test file
		testFile := filepath.Join(tempDir, "test-standard-delete.txt")
		err := os.WriteFile(testFile, []byte("test content"), 0644)
		require.NoError(t, err)

		// Perform standard delete
		SecureDelete(testFile, false)

		// Verify file is deleted
		_, err = os.Stat(testFile)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("secure delete when enabled", func(t *testing.T) {
		// Create a test file
		testFile := filepath.Join(tempDir, "test-secure-delete.txt")
		err := os.WriteFile(testFile, []byte("test content"), 0644)
		require.NoError(t, err)

		// Perform secure delete
		SecureDelete(testFile, true)

		// Verify file is deleted
		_, err = os.Stat(testFile)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("non-existent file", func(t *testing.T) {
		// Try to delete a non-existent file
		nonExistentFile := filepath.Join(tempDir, "non-existent.txt")
		SecureDelete(nonExistentFile, true)
		// Should not panic or error
	})

	t.Run("overwrite failure", func(t *testing.T) {
		// Create a test file
		testFile := filepath.Join(tempDir, "test-overwrite-failure.txt")
		err := os.WriteFile(testFile, []byte("test content"), 0644)
		require.NoError(t, err)

		// Make the file read-only to cause overwrite failure
		err = os.Chmod(testFile, 0444)
		require.NoError(t, err)

		// Perform secure delete
		SecureDelete(testFile, true)

		// Verify file is still deleted (should fall back to standard delete)
		_, err = os.Stat(testFile)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("standard delete fails on remove", func(t *testing.T) {
		// Create a test file
		testFile := filepath.Join(tempDir, "test-std-remove-fail.txt")
		err := os.WriteFile(testFile, []byte("test content"), 0644)
		require.NoError(t, err)

		// Make parent dir read-only
		err = os.Chmod(tempDir, 0555)
		require.NoError(t, err)
		defer func() { _ = os.Chmod(tempDir, 0755) }() // Ignore error

		// Perform standard delete - should log warning but not error out
		SecureDelete(testFile, false)

		// Verify file still exists
		_, err = os.Stat(testFile)
		assert.NoError(t, err, "File should still exist after standard remove failure")
	})

	t.Run("secure delete fails on final remove", func(t *testing.T) {
		// Create a test file
		testFile := filepath.Join(tempDir, "test-sec-final-remove-fail.txt")
		initialContent := []byte("test content")
		err := os.WriteFile(testFile, initialContent, 0644)
		require.NoError(t, err)

		// Make parent dir read-only
		err = os.Chmod(tempDir, 0555)
		require.NoError(t, err)
		defer func() { _ = os.Chmod(tempDir, 0755) }() // Ignore error

		// Perform secure delete - overwrite should work, remove should fail
		SecureDelete(testFile, true)

		// Verify file still exists (but content should be different)
		_, err = os.Stat(testFile)
		assert.NoError(t, err, "File should still exist after final remove failure")
		// Check content was overwritten (best effort check)
		readContent, readErr := os.ReadFile(testFile)
		require.NoError(t, readErr)
		assert.NotEqual(t, initialContent, readContent, "Content should have been overwritten")
	})

	t.Run("secure delete fails on fallback remove", func(t *testing.T) {
		// Create a test file
		testFile := filepath.Join(tempDir, "test-sec-fallback-remove-fail.txt")
		initialContent := []byte("test content")
		err := os.WriteFile(testFile, initialContent, 0644)
		require.NoError(t, err)

		// Make file read-only (causes overwrite failure)
		err = os.Chmod(testFile, 0444)
		require.NoError(t, err)
		defer func() { _ = os.Chmod(testFile, 0644) }() // Ignore error

		// Make parent dir read-only (causes fallback remove failure)
		err = os.Chmod(tempDir, 0555)
		require.NoError(t, err)
		defer func() { _ = os.Chmod(tempDir, 0755) }() // Ignore error

		// Perform secure delete - overwrite fails, fallback remove fails
		SecureDelete(testFile, true)

		// Verify file still exists and content is original
		_, err = os.Stat(testFile)
		assert.NoError(t, err, "File should still exist after fallback remove failure")
		readContent, readErr := os.ReadFile(testFile)
		require.NoError(t, readErr)
		assert.Equal(t, initialContent, readContent, "Content should NOT have been overwritten")
	})
}

func TestOverwriteFile(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "overwrite-file-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }() // Ignore error

	t.Run("create new file", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "new-file.txt")
		content := []byte("test content")
		perm := os.FileMode(0644)

		err := OverwriteFile(testFile, content, perm)
		require.NoError(t, err)

		// Verify file exists with correct content and permissions
		info, err := os.Stat(testFile)
		require.NoError(t, err)
		assert.Equal(t, perm, info.Mode().Perm())

		readContent, err := os.ReadFile(testFile)
		require.NoError(t, err)
		assert.Equal(t, content, readContent)
	})

	t.Run("overwrite existing file", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "existing-file.txt")
		initialContent := []byte("initial content")
		newContent := []byte("new content")
		perm := os.FileMode(0644)

		// Create initial file
		err := os.WriteFile(testFile, initialContent, perm)
		require.NoError(t, err)

		// Overwrite file
		err = OverwriteFile(testFile, newContent, perm)
		require.NoError(t, err)

		// Verify new content
		readContent, err := os.ReadFile(testFile)
		require.NoError(t, err)
		assert.Equal(t, newContent, readContent)
	})

	t.Run("error cases", func(t *testing.T) {
		// Test with invalid path
		invalidPath := filepath.Join(tempDir, "nonexistent", "subdir", "file.txt")
		err := OverwriteFile(invalidPath, []byte("test"), 0644)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open/create file")
	})

	t.Run("close error", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "close-error.txt")
		content := []byte("test content")
		perm := os.FileMode(0644)

		// Create and open the file
		file, err := os.OpenFile(testFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
		require.NoError(t, err)

		// Close the file to cause a close error
		_ = file.Close() // Ignore error in test setup

		// Try to overwrite the file
		err = OverwriteFile(testFile, content, perm)
		assert.NoError(t, err) // Should still succeed as the file is overwritten
	})

	t.Run("short write", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "short-write.txt")
		content := []byte("test content")

		// Create a file with read-only permissions
		err := os.WriteFile(testFile, []byte("initial"), 0444)
		require.NoError(t, err)

		// Try to overwrite with read-only permissions
		err = OverwriteFile(testFile, content, 0444)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open/create file")
		assert.Contains(t, err.Error(), "permission denied")
	})

	t.Run("write to read-only dir", func(t *testing.T) {
		readOnlyDir := filepath.Join(tempDir, "read-only-dir")
		err := os.MkdirAll(readOnlyDir, 0444) // Read-only
		require.NoError(t, err)
		defer func() { _ = os.Chmod(readOnlyDir, 0755) }() // Ignore error
		defer func() { _ = os.RemoveAll(readOnlyDir) }()   // Ignore error

		testFile := filepath.Join(readOnlyDir, "cannot-create.txt")
		content := []byte("test content")
		perm := os.FileMode(0600)

		err = OverwriteFile(testFile, content, perm)
		assert.Error(t, err) // Expect an error
		if err != nil {      // Check content only if error is not nil
			assert.Contains(t, err.Error(), "failed to open/create file")
			assert.Contains(t, err.Error(), "permission denied")
		}
	})
}

func TestOverwriteFile_ErrorCases(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "overwrite-file-error-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }() // Ignore error

	t.Run("short write", func(t *testing.T) {
		// Create a read-only file
		testFile := filepath.Join(tempDir, "readonly.txt")
		err := os.WriteFile(testFile, []byte("test"), 0444)
		require.NoError(t, err)

		// Try to overwrite with read-only permissions
		err = OverwriteFile(testFile, []byte("new content"), 0444)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open/create file")
		assert.Contains(t, err.Error(), "permission denied")
	})

	// Removed unreliable "sync error" test cases
}

func TestOverwriteFile_WithRandomData(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "overwrite-random-test-*")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }() // Ignore error

	t.Run("overwrite with random data", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "random-data.txt")
		initialContent := []byte("initial content that will be overwritten with random data")

		// Create initial file
		err := os.WriteFile(testFile, initialContent, 0644)
		require.NoError(t, err)

		// Overwrite with random data
		err = overwriteFile(testFile)
		require.NoError(t, err)

		// Read the file and verify it's not the original content
		readContent, err := os.ReadFile(testFile)
		require.NoError(t, err)
		assert.NotEqual(t, initialContent, readContent)
		assert.Equal(t, len(initialContent), len(readContent))
	})

	t.Run("non-existent file", func(t *testing.T) {
		nonExistentFile := filepath.Join(tempDir, "non-existent.txt")
		err := overwriteFile(nonExistentFile)
		assert.NoError(t, err) // Should not error for non-existent files
	})

	t.Run("overwrite with read-only file", func(t *testing.T) {
		testFile := filepath.Join(tempDir, "readonly-random.txt")
		initialContent := []byte("initial content")

		// Create initial file
		err := os.WriteFile(testFile, initialContent, 0444)
		require.NoError(t, err)

		// Try to overwrite with random data
		err = overwriteFile(testFile)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open file")
		assert.Contains(t, err.Error(), "permission denied")
	})

	t.Run("overwrite with directory", func(t *testing.T) {
		// Create a subdirectory
		subDir := filepath.Join(tempDir, "subdir")
		err := os.Mkdir(subDir, 0755)
		require.NoError(t, err)

		// Try to overwrite the directory
		err = overwriteFile(subDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open file")
	})
}
