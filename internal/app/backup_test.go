package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"reflect"
	"testing"
)

// Moved fileEntry to package level
type fileEntry struct {
	name    string
	content string
}

func TestParseSHA256SUMS(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		want    map[string]string
	}{
		{
			name: "valid checksums file",
			content: []byte(
				"checksum1  file1.txt\n" +
					"checksum2  file2.txt\n" +
					"checksum3  another/file.zip\n",
			),
			want: map[string]string{
				"file1.txt":        "checksum1",
				"file2.txt":        "checksum2",
				"another/file.zip": "checksum3",
			},
		},
		{
			name:    "empty content",
			content: []byte(""),
			want:    map[string]string{},
		},
		{
			name: "content with empty lines and spaces",
			content: []byte(
				"\n" +
					"  checksumA  fileA.dat  \n" + // Extra spaces around filename
					"\n" +
					"checksumB  fileB.dat\n" +
					"\n",
			),
			want: map[string]string{
				"fileA.dat": "checksumA",
				"fileB.dat": "checksumB",
			},
		},
		{
			name: "content with invalid lines",
			content: []byte(
				"checksumX  fileX.txt\n" +
					"justoneword\n" + // Invalid line
					"checksumY  fileY.txt\n" +
					"too many words in this line\n", // Invalid line
			),
			want: map[string]string{
				"fileX.txt": "checksumX",
				"fileY.txt": "checksumY",
			},
		},
		{
			name:    "nil content",
			content: nil,
			want:    map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSHA256SUMS(tt.content)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseSHA256SUMS() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyInternalChecksums(t *testing.T) {
	tests := []struct {
		name           string
		files          []fileEntry
		shaSumsContent string
		corruptArchive bool // To simulate various archive errors
		noShaFile      bool // To simulate missing SHA256SUMS
		wantErr        bool
		expectedError  string // Optional: check for specific error message substring
	}{
		{
			name: "valid archive",
			files: []fileEntry{
				{name: "file1.txt", content: "hello world"},
				{name: "data/file2.dat", content: "some data here"},
			},
			shaSumsContent: generateShaSums([]fileEntry{
				{name: "file1.txt", content: "hello world"},
				{name: "data/file2.dat", content: "some data here"},
			}),
			wantErr: false,
		},
		{
			name: "SHA256SUMS file not found",
			files: []fileEntry{
				{name: "file1.txt", content: "hello world"},
			},
			noShaFile:     true,
			wantErr:       true,
			expectedError: "SHA256SUMS file not found in the archive",
		},
		{
			name: "file listed in SHA256SUMS not found in archive",
			files: []fileEntry{
				// file2.txt is in shaSumsContent but not in the archive files
				{name: "file1.txt", content: "hello"},
			},
			shaSumsContent: generateShaSums([]fileEntry{
				{name: "file1.txt", content: "hello"},
				{name: "file2.txt", content: "world"},
			}),
			wantErr:       true,
			expectedError: "file file2.txt listed in SHA256SUMS not found in archive",
		},
		{
			name: "checksum mismatch",
			files: []fileEntry{
				{name: "file1.txt", content: "actual content"},
			},
			// shaSumsContent will be for "expected content", causing a mismatch
			shaSumsContent: generateShaSums([]fileEntry{
				{name: "file1.txt", content: "expected content"},
			}),
			wantErr:       true,
			expectedError: "checksum mismatch for file1.txt",
		},
		{
			name:           "corrupt archive - not gzip",
			corruptArchive: true,
			wantErr:        true,
			expectedError:  "gzip error: gzip: invalid header", // Error from gzip.NewReader
		},
		{
			name:           "empty archive data",
			files:          []fileEntry{}, // No files
			shaSumsContent: "",            // Empty SHA256SUMS
			// This will lead to verifyInternalChecksums trying to read an empty byte slice as gzip, causing an error.
			// If createTestArchive produces empty bytes for this, verifyInternalChecksums gets nil.
			// The function being tested expects gzipped data, so empty input is an error.
			// If createTestArchive creates a valid empty gzipped tar, then SHA256SUMS not found would be the error.
			// Actually, an empty tar.gz is valid but will fail the SHA256SUMS check if that's created.
			// If the input data to verifyInternalChecksums is simply an empty slice (not a valid gz), it's a gzip error.
			// The existing test structure for tt.corruptArchive handles this if we want to send raw empty bytes.
			// For this case, let's make it an empty but valid tar.gz, so it should fail on missing SHA256SUMS.
			noShaFile:     true, // This will make createTestArchive create an empty tar with no SHA256SUMS
			wantErr:       true,
			expectedError: "SHA256SUMS file not found in the archive",
		},
		{
			name:           "archive with only SHA256SUMS (empty)",
			files:          []fileEntry{}, // No actual files
			shaSumsContent: "",            // Empty SHA256SUMS content
			// verifyInternalChecksums will parse empty sums, find no files to check, and succeed.
			wantErr: false,
		},
		{
			name:           "archive with only SHA256SUMS (non-empty but for non-existent files)",
			files:          []fileEntry{}, // No actual files in tar
			shaSumsContent: generateShaSums([]fileEntry{{name: "ghost.txt", content: "boo"}}),
			wantErr:        true,
			expectedError:  "file ghost.txt listed in SHA256SUMS not found in archive",
		},
		{
			name: "corrupt tar content (valid gzip)",
			// We will set archiveData directly for this test case, so files/shaSumsContent are not used
			// The verifyInternalChecksums function will receive data that is gzipped,
			// but the uncompressed content is not a valid tar stream.
			wantErr:       true,
			expectedError: "tar error: unexpected EOF", // Adjusted expected error
			// This specific error message "tar: Unrecognized archive format" comes from running it locally.
			// It might be slightly different depending on the tar library version or Go version.
			// A more generic check like "tar error" might be safer if this is too specific.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var archiveData []byte
			var err error

			if tt.name == "corrupt tar content (valid gzip)" {
				gzippedBadData, gzErr := gzipDataBytes([]byte("this is not a tar archive"))
				if gzErr != nil {
					t.Fatalf("failed to gzip data for test '%s': %v", tt.name, gzErr)
				}
				archiveData = gzippedBadData
			} else if tt.corruptArchive {
				archiveData = []byte("not a valid gzip tar")
			} else {
				archiveData, err = createTestArchive(tt.files, tt.shaSumsContent, tt.noShaFile)
				if err != nil {
					t.Fatalf("failed to create test archive: %v", err)
				}
			}

			err = verifyInternalChecksums(archiveData)

			if (err != nil) != tt.wantErr {
				t.Errorf("verifyInternalChecksums() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.expectedError != "" {
				if !bytes.Contains([]byte(err.Error()), []byte(tt.expectedError)) {
					t.Errorf("verifyInternalChecksums() error = %v, expected to contain %q", err, tt.expectedError)
				}
			}
		})
	}
}

// Helper function to create a gzipped tar archive for testing
func createTestArchive(files []fileEntry, shaSumsContent string, noShaFile bool) ([]byte, error) {
	buf := new(bytes.Buffer)
	gzw := gzip.NewWriter(buf)
	tw := tar.NewWriter(gzw)

	// Add files to the tar archive
	for _, file := range files {
		hdr := &tar.Header{
			Name: file.name,
			Mode: 0600,
			Size: int64(len(file.content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write([]byte(file.content)); err != nil {
			return nil, err
		}
	}

	// Add SHA256SUMS file unless instructed not to
	if !noShaFile {
		shaHdr := &tar.Header{
			Name: "SHA256SUMS",
			Mode: 0600,
			Size: int64(len(shaSumsContent)),
		}
		if err := tw.WriteHeader(shaHdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write([]byte(shaSumsContent)); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gzw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Helper function to generate SHA256SUMS content
func generateShaSums(files []fileEntry) string {
	var sums string
	for _, file := range files {
		h := sha256.New()
		h.Write([]byte(file.content))
		sums += fmt.Sprintf("%x  %s\n", h.Sum(nil), file.name)
	}
	return sums
}

// Helper function to gzip arbitrary data
func gzipDataBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	if _, err := gzw.Write(data); err != nil {
		return nil, err
	}
	if err := gzw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- Mocks ---

type mockVaultClient struct {
	BackupFn func(ctx context.Context, w io.Writer) error
	// To store what was written by the Backup function if needed for assertions
	writtenData *bytes.Buffer
}

func (m *mockVaultClient) Backup(ctx context.Context, w io.Writer) error {
	if m.BackupFn != nil {
		// If writtenData buffer is provided, tee the writes to it
		if m.writtenData != nil {
			return m.BackupFn(ctx, io.MultiWriter(w, m.writtenData))
		}
		return m.BackupFn(ctx, w)
	}
	return fmt.Errorf("BackupFn not set in mockVaultClient")
}

func (m *mockVaultClient) Restore(ctx context.Context, r io.Reader) error {
	// Not needed for testing the Backup function in backup.go
	return fmt.Errorf("Restore not implemented in mock")
}

type mockS3Client struct {
	PutObjectFn        func(ctx context.Context, key string, r io.Reader) error
	GetObjectFn        func(ctx context.Context, key string) (io.ReadCloser, error)
	ResolveBackupKeyFn func(ctx context.Context) (string, error)

	// To capture arguments for assertions
	putObjectCalled bool
	putObjectKey    string
	putObjectData   []byte
}

func (m *mockS3Client) PutObject(ctx context.Context, key string, r io.Reader) error {
	m.putObjectCalled = true
	m.putObjectKey = key
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("mockS3Client failed to read from reader: %w", err)
	}
	m.putObjectData = data

	if m.PutObjectFn != nil {
		return m.PutObjectFn(ctx, key, bytes.NewReader(data)) // Pass a new reader with the captured data
	}
	return fmt.Errorf("PutObjectFn not set in mockS3Client")
}

func (m *mockS3Client) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
	// Not needed for testing the Backup function in backup.go
	if m.GetObjectFn != nil {
		return m.GetObjectFn(ctx, key)
	}
	return nil, fmt.Errorf("GetObjectFn not implemented in mock")
}

func (m *mockS3Client) ResolveBackupKey(ctx context.Context) (string, error) {
	// Not needed for testing the Backup function in backup.go
	if m.ResolveBackupKeyFn != nil {
		return m.ResolveBackupKeyFn(ctx)
	}
	return "", fmt.Errorf("ResolveBackupKeyFn not implemented in mock")
}

// --- TestBackup ---

func TestBackup(t *testing.T) {
	// Basic setup for a successful backup to create valid archive data
	validFiles := []fileEntry{
		{name: "file1.txt", content: "hello from vault"},
	}
	validShaSums := generateShaSums(validFiles)
	validArchiveData, err := createTestArchive(validFiles, validShaSums, false)
	if err != nil {
		t.Fatalf("Failed to create valid test archive for TestBackup setup: %v", err)
	}

	tests := []struct {
		name             string
		vaultClientSetup func(m *mockVaultClient) // Setup for vault client mock
		s3ClientSetup    func(m *mockS3Client)    // Setup for S3 client mock
		wantErr          bool
		expectedError    string // Substring of the expected error message
		checkS3Put       bool   // Whether to check S3 PutObject was called with correct data
	}{
		{
			name: "successful backup",
			vaultClientSetup: func(m *mockVaultClient) {
				m.BackupFn = func(ctx context.Context, w io.Writer) error {
					_, err := w.Write(validArchiveData)
					return err
				}
			},
			s3ClientSetup: func(m *mockS3Client) {
				m.PutObjectFn = func(ctx context.Context, key string, r io.Reader) error {
					// We can add more assertions here on the key if needed
					return nil
				}
			},
			wantErr:    false,
			checkS3Put: true,
		},
		{
			name: "vault client backup fails",
			vaultClientSetup: func(m *mockVaultClient) {
				m.BackupFn = func(ctx context.Context, w io.Writer) error {
					return fmt.Errorf("vault broke")
				}
			},
			s3ClientSetup: func(m *mockS3Client) { /* No setup needed, won't be called */ },
			wantErr:       true,
			expectedError: "creating raft snapshot failed: vault broke",
		},
		{
			name: "snapshot verification fails due to bad vault data",
			vaultClientSetup: func(m *mockVaultClient) {
				m.BackupFn = func(ctx context.Context, w io.Writer) error {
					_, err := w.Write([]byte("this is not a valid gzip tar"))
					return err
				}
			},
			s3ClientSetup: func(m *mockS3Client) { /* No setup needed */ },
			wantErr:       true,
			expectedError: "snapshot verification failed: gzip error: gzip: invalid header",
		},
		{
			name: "s3 client PutObject fails",
			vaultClientSetup: func(m *mockVaultClient) {
				m.BackupFn = func(ctx context.Context, w io.Writer) error {
					_, err := w.Write(validArchiveData)
					return err
				}
			},
			s3ClientSetup: func(m *mockS3Client) {
				m.PutObjectFn = func(ctx context.Context, key string, r io.Reader) error {
					return fmt.Errorf("s3 broke")
				}
			},
			wantErr:       true,
			expectedError: "s3 upload operation failed: s3 broke",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockVC := &mockVaultClient{writtenData: new(bytes.Buffer)}
			mockS3 := &mockS3Client{}

			if tt.vaultClientSetup != nil {
				tt.vaultClientSetup(mockVC)
			}
			if tt.s3ClientSetup != nil {
				tt.s3ClientSetup(mockS3)
			}

			ctx := context.Background()
			err := Backup(ctx, mockVC, mockS3)

			if (err != nil) != tt.wantErr {
				t.Errorf("Backup() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.expectedError != "" {
				if !bytes.Contains([]byte(err.Error()), []byte(tt.expectedError)) {
					t.Errorf("Backup() error = %v, expected to contain %q", err, tt.expectedError)
				}
			}

			if tt.checkS3Put {
				if !mockS3.putObjectCalled {
					t.Errorf("S3 PutObject was not called, but was expected")
				}
				// We can also check mockS3.putObjectKey for correct naming pattern if desired
				// And compare mockS3.putObjectData with what vaultClient wrote (mockVC.writtenData)
				// For now, let's ensure the data passed to S3 is what Vault produced.
				// Note: vaultClient's BackupFn writes `validArchiveData` in the success case.
				if !bytes.Equal(mockS3.putObjectData, validArchiveData) {
					t.Errorf("Data written to S3 does not match data from Vault. S3 got: %d bytes, Vault wrote: %d bytes", len(mockS3.putObjectData), len(validArchiveData))
				}
			}
		})
	}
}
