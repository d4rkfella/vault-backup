package util

import (
	"crypto/rand"
	"fmt"
	// "io" // Unused import
	"os"
	"strings"

	"github.com/rs/zerolog/log"
)

// RedactURL attempts to mask potentially sensitive parts of a URL string for safe logging.
// It currently masks the hostname part before the first dot.
// Example: "http://sensitive.example.com/path" -> "http://***.example.com/path"
func RedactURL(url string) string {
	if url == "" {
		return "none"
	}
	parts := strings.SplitN(url, ".", 2)
	if len(parts) > 1 {
		return fmt.Sprintf("***.%s", parts[1])
	}
	return "***"
}

// SanitizePath attempts to mask potentially sensitive parts of a file path string for safe logging.
// It currently masks the 4th path component onwards.
// Example: "/var/log/myapp/very/long/path/file.log" -> "/var/log/myapp/***/long/path/file.log"
// TODO: Revisit this logic - currently masks parts *after* the 4th, maybe mask *before* or specific parts?
// The current implementation based on splitting might not be ideal for all path types.
func SanitizePath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 3 {
		// Example: Mask the 3rd part onwards if it's a deep path (Changed from parts[3])
		parts[2] = "***"
	}
	return strings.Join(parts, "/")
}

// RedactKey masks most characters of a sensitive key or token string for safe logging,
// showing only the first and last few characters.
// Example: "aVeryLongSecretTokenValue" -> "aVer***lue"
func RedactKey(key string) string {
	if len(key) < 8 {
		return "***" // Too short to redact meaningfully
	}
	// Show first 4 and last 4 characters
	return key[:4] + "***" + key[len(key)-4:]
}

// SecureDelete attempts to securely delete a file by first overwriting it with random data.
// It only performs the overwrite if secureDeleteEnabled is true.
// It logs errors encountered during overwrite or removal but does not return them.
func SecureDelete(path string, secureDeleteEnabled bool) {
	sanitizedPath := SanitizePath(path)
	if !secureDeleteEnabled {
		log.Debug().Str("component", "util").Str("path", sanitizedPath).Msg("Performing standard file removal (secure delete disabled)")
		if err := os.Remove(path); err != nil {
			log.Warn().Err(err).Str("path", sanitizedPath).Msg("Failed to remove file")
		}
		return
	}

	log.Debug().Str("component", "util").Str("path", sanitizedPath).Msg("Starting secure delete")
	if err := overwriteFile(path); err != nil { // Call UNEXPORTED overwriteFile (random data)
		log.Error().Err(err).Str("path", sanitizedPath).Msg("Failed to overwrite file during secure delete, attempting standard remove")
		// Fallback to standard remove even if overwrite fails
		if removeErr := os.Remove(path); removeErr != nil {
			log.Error().Err(removeErr).Str("path", sanitizedPath).Msg("Failed standard file removal after overwrite failure")
		}
		return
	}

	// Overwrite succeeded, now remove the file.
	if err := os.Remove(path); err != nil {
		log.Error().Err(err).Str("path", sanitizedPath).Msg("Failed to remove file after successful overwrite")
	}
	log.Debug().Str("component", "util").Str("path", sanitizedPath).Msg("Secure delete completed")
}

// OverwriteFile attempts to overwrite the specified file with specific content and permissions.
// If the file exists, it's truncated. If not, it's created.
// This replaces the previous internal overwriteFile which only did random data.
func OverwriteFile(path string, content []byte, perm os.FileMode) error {
	sanitizedPath := SanitizePath(path)
	log.Debug().Str("path", sanitizedPath).Int("bytes", len(content)).Msgf("Writing/Overwriting file with permissions %o", perm)

	// Open file with flags to create if not exists, truncate if exists, write-only.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("failed to open/create file %s for writing: %w", sanitizedPath, err)
	}
	// Use a named return for the primary error, defer close and error checking.
	var opErr error // Holds the first error encountered (write, sync, or close)
	defer func() {
		closeErr := file.Close()
		if opErr == nil && closeErr != nil { // Only assign closeErr if no other error occurred
			opErr = fmt.Errorf("failed to close file %s after writing: %w", sanitizedPath, closeErr)
			log.Warn().Err(opErr).Str("path", sanitizedPath).Msg("Error captured during file close")
		} else if closeErr != nil {
			// Log the close error even if we're returning a different primary error
			log.Warn().Err(closeErr).Str("path", sanitizedPath).Msg("File close failed (returning earlier error)")
		}
	}()

	// Write the content.
	n, err := file.Write(content)
	if err != nil {
		opErr = fmt.Errorf("failed to write content to file %s: %w", sanitizedPath, err)
		return opErr // Return immediately
	}
	if n != len(content) {
		opErr = fmt.Errorf("short write to file %s: wrote %d bytes, expected %d", sanitizedPath, n, len(content))
		return opErr // Return immediately
	}

	// Ensure data is flushed to disk.
	if err = file.Sync(); err != nil {
		opErr = fmt.Errorf("failed to sync file %s after writing: %w", sanitizedPath, err)
		return opErr // Return immediately
	}

	// If write and sync succeeded, opErr is still nil here.
	// The deferred function will run, potentially setting opErr if close fails.
	return opErr // Return the first error encountered (write, sync, or close)
}

// overwriteFile attempts to overwrite the specified file with random data. (UNEXPORTED)
// This is a best-effort approach and effectiveness depends on the filesystem and OS.
// It currently performs a single pass.
// Returns an error if overwriting fails.
func overwriteFile(path string) error {
	sanitizedPath := SanitizePath(path)
	// Open file for writing only.
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			log.Warn().Str("path", sanitizedPath).Msg("File not found for overwriting, skipping")
			return nil // Not an error if file doesn't exist.
		}
		return fmt.Errorf("failed to open file %s for overwrite: %w", sanitizedPath, err)
	}
	// Ensure file is closed.
	defer func() {
		if err := file.Close(); err != nil {
			log.Warn().Err(err).Str("path", sanitizedPath).Msg("Failed to close file during secure overwrite")
		}
	}()

	// Get file size to determine how much data to write.
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file %s for overwrite: %w", sanitizedPath, err)
	}
	size := fileInfo.Size()

	log.Debug().Str("path", sanitizedPath).Int64("size", size).Msg("Overwriting file with random data (single pass)")

	// Overwrite with random data using a buffer.
	const bufferSize = 4096
	buf := make([]byte, bufferSize)
	written := int64(0)
	for written < size {
		// Read random bytes into buffer.
		n_read, randErr := rand.Read(buf)
		if randErr != nil {
			return fmt.Errorf("failed to read random data for overwrite: %w", randErr)
		}
		// Determine how much of the buffer to write (handle last partial write).
		towrite := n_read
		if written+int64(towrite) > size {
			towrite = int(size - written)
		}

		// Write the random bytes.
		n_written, writeErr := file.Write(buf[:towrite])
		if writeErr != nil {
			return fmt.Errorf("failed to write overwrite data (pass 1) for %s: %w", sanitizedPath, writeErr)
		}
		if n_written != towrite {
			return fmt.Errorf("short write during overwrite (pass 1) for %s: wrote %d, expected %d", sanitizedPath, n_written, towrite)
		}
		written += int64(n_written)
	}

	// Ensure data is flushed to disk.
	if err = file.Sync(); err != nil {
		return fmt.Errorf("failed to sync overwritten file %s: %w", sanitizedPath, err)
	}

	log.Debug().Str("path", sanitizedPath).Msg("File overwrite complete")
	return nil
}

/* // Comment block removed as it's now the active unexported function
 */
