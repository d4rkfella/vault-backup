package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go/service/s3/s3manager/s3manageriface"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/d4rkfella/vault-backup/internal/config"
	"github.com/d4rkfella/vault-backup/internal/retry"
	"github.com/d4rkfella/vault-backup/internal/util"  // Import util
	"github.com/d4rkfella/vault-backup/internal/vault" // For SecureString
)

// Client wraps the AWS session and configuration for S3 operations.
type Client struct {
	cfg  *config.Config
	sess *session.Session
	// Maybe add internal s3 and s3manager clients here if needed frequently?
}

// --- Retry Config ---
const (
	defaultMaxAttempts  = 4               // Slightly fewer attempts for S3?
	defaultInitialDelay = 1 * time.Second // Longer initial delay for S3
	defaultMaxDelay     = 30 * time.Second
)

var defaultRetryConfig = retry.Config{
	MaxAttempts:  defaultMaxAttempts,
	InitialDelay: defaultInitialDelay,
	MaxDelay:     defaultMaxDelay,
}

// --- End Retry Config ---

// --- Interfaces for Mocking (Removed as they will be applied to Client methods if needed) ---

// --- Provider Functions (Removed as Client methods will create clients directly) ---

// --- Retry Logic Helper ---

// isTransientS3Error checks if the error is likely a temporary issue suitable for retrying S3 operations.
// This includes common network errors and specific AWS/S3 transient error codes.
// NOTE: This function is now used as the IsRetryableFunc for the retry package.
func isTransientS3Error(err error) bool {
	if err == nil {
		return false
	}

	// Check for context cancellation/timeout first
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return false // Don't retry if context is done
	}

	// Check for common network errors
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true // Network timeout
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true // Connection closed prematurely
	}

	// Check for AWS SDK specific retryable errors
	var aerr awserr.Error
	if errors.As(err, &aerr) {
		switch aerr.Code() {
		case "SlowDown",
			"RequestTimeout",
			"Throttling",
			"InternalError":
			return true
		default:
			return false
		}
	}

	log.Debug().Err(err).Msg("Encountered non-transient S3 error")
	return false
}

// readCounter wraps an io.Reader, counting the total bytes read.
// Used internally by UploadToS3 for monitoring upload progress and calculating rate.
type readCounter struct {
	total int64     // Total bytes read so far.
	r     io.Reader // The underlying reader.
	path  string    // File path being read (for logging).
	size  int64     // Total expected size of the file.
	start time.Time // Start time of the read operation.
}

// newReadCounter creates a new read counter wrapping the given reader.
func newReadCounter(r io.Reader, path string, size int64) *readCounter {
	return &readCounter{
		r:     r,
		path:  path,
		size:  size,
		start: time.Now(),
	}
}

// Read reads from the underlying reader, updating the total bytes read count.
func (rc *readCounter) Read(p []byte) (n int, err error) {
	n, err = rc.r.Read(p)
	rc.total += int64(n)
	// TODO: Optional: Add periodic progress logging here based on time elapsed or bytes read.
	return
}

// --- Need package variables to allow mocking internal SDK client creation ---
// Define these at the package level in s3.go or a test helper file.

var s3New = func(sess *session.Session, cfgs ...*aws.Config) s3iface.S3API {
	return s3.New(sess, cfgs...)
}

var s3managerNewUploader = func(sess *session.Session, options ...func(*s3manager.Uploader)) s3manageriface.UploaderAPI {
	return s3manager.NewUploader(sess, options...)
}

// NewClient creates and verifies a new AWS session and returns an S3 Client.
// RENAMED from NewAWSSession, returns *Client, removes s3ClientProvider arg.
func NewClient(
	ctx context.Context,
	cfg *config.Config,
	accessKey, secretKey vault.SecureString,
	// s3ClientProvider S3ClientProvider, // REMOVED Provider
) (*Client, error) {
	log.Debug().Str("component", "s3").Msg("Creating AWS session")
	awsConfig := aws.NewConfig() // aws.Config (value)

	// Use Static credentials from Vault SecureStrings.
	creds := credentials.NewStaticCredentials(accessKey.String(), secretKey.String(), "")
	// Validate credentials immediately (basic check, not API call).
	_, err := creds.Get()
	if err != nil {
		return nil, fmt.Errorf("invalid AWS credentials provided: %w", err)
	}
	awsConfig.Credentials = creds // Assign directly

	// Set region, warning if discovery might be needed.
	if cfg.AWSRegion != "" && cfg.AWSRegion != "auto" {
		awsConfig.Region = aws.String(cfg.AWSRegion) // Assign directly
	} else {
		log.Warn().Str("component", "s3").Msg("AWS_REGION is empty or 'auto', region discovery might occur")
	}

	// Set custom endpoint if provided (for S3-compatible storage).
	if cfg.AWSEndpoint != "" {
		// Redact endpoint URL
		log.Debug().Str("component", "s3").Str("endpoint", util.RedactURL(cfg.AWSEndpoint)).Msg("Using custom S3 endpoint")
		awsConfig.Endpoint = aws.String(cfg.AWSEndpoint) // Assign directly
		awsConfig.S3ForcePathStyle = aws.Bool(true)      // Assign directly
	}

	// --- AWS SDK Logging Setup --- //
	awsLogLevel := aws.LogLevel(aws.LogOff) // Returns *aws.LogLevelType
	appLogLevel := zerolog.GlobalLevel()    // Get level set by logging.Init
	// Map zerolog levels to appropriate AWS SDK log levels
	switch appLogLevel {
	case zerolog.TraceLevel, zerolog.DebugLevel:
		// Enable debug logging, including HTTP request bodies
		awsLogLevel = aws.LogLevel(aws.LogDebugWithHTTPBody | aws.LogDebugWithRequestRetries | aws.LogDebugWithRequestErrors)
	case zerolog.InfoLevel, zerolog.WarnLevel, zerolog.ErrorLevel:
		// For higher levels, only log request errors
		awsLogLevel = aws.LogLevel(aws.LogDebugWithRequestErrors)
	}

	awsConfig.LogLevel = awsLogLevel // Assign directly
	if *awsLogLevel != aws.LogOff {  // Dereference for comparison
		// Provide the SDK with a logger if logging is enabled.
		// Using aws.NewDefaultLogger() sends logs to stderr.
		// TODO: Could potentially integrate with zerolog using a custom logger adapter.
		awsConfig.Logger = aws.NewDefaultLogger() // Assign directly
		log.Debug().Str("component", "s3").Str("aws_log_level", fmt.Sprintf("%v", *awsLogLevel)).Msg("AWS SDK logging enabled")
	} else {
		log.Debug().Str("component", "s3").Msg("AWS SDK logging disabled")
	}
	// --- End AWS SDK Logging Setup --- //

	// Configure SDK defaults (retries, etc.).
	awsConfig.MaxRetries = aws.Int(3) // Assign directly

	// Create the session object.
	sessOpts := session.Options{
		Config:            *awsConfig,
		SharedConfigState: session.SharedConfigDisable,
	}
	sess, err := session.NewSessionWithOptions(sessOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	// --- Retry Block for Session Verification using custom retry --- //
	// Create the S3 client using the package variable (which can be mocked in tests)
	s3client := s3New(sess) // Use the package variable instead of direct s3.New
	var verificationErr error

	verifyOperation := func(opCtx context.Context) error {
		log.Trace().Str("component", "s3").Str("bucket", cfg.S3Bucket).Msg("Attempting S3 session verification (GetBucketLocation)") // Trace for less noise
		_, err = s3client.GetBucketLocationWithContext(opCtx, &s3.GetBucketLocationInput{
			Bucket: aws.String(cfg.S3Bucket),
		})
		// Return error to be checked by isTransientS3Error
		return err
	}

	// Execute the verification with retry
	verificationErr = retry.ExecuteWithRetry(ctx, defaultRetryConfig, verifyOperation, isTransientS3Error, "S3SessionVerification")

	// Check final error after retries
	if verificationErr != nil {
		log.Error().Err(verificationErr).Str("bucket", cfg.S3Bucket).Msg("S3 session verification failed after retries")
		// Consider returning error here to prevent proceeding with a potentially bad session
		return nil, fmt.Errorf("failed initial S3 bucket check after retries for bucket %s: %w", cfg.S3Bucket, verificationErr)
	}
	// --- End Retry Block --- //

	log.Info().Str("component", "s3").Msg("AWS session created successfully")
	// Return the wrapped client struct
	return &Client{
		cfg:  cfg,
		sess: sess,
	}, nil
}

// Upload uploads the specified local file to S3.
// It is now a method on the Client struct.
// Includes custom retry logic for the upload operation.
func (c *Client) Upload(
	ctx context.Context,
	filePath string,
) error {
	// Use cfg and sess from the client struct
	cfg := c.cfg
	sess := c.sess

	// Sanitize file path for logging.
	sanitizedFilePath := util.SanitizePath(filePath)
	log.Info().Str("component", "s3").Str("file", sanitizedFilePath).Str("bucket", cfg.S3Bucket).Msg("Starting S3 upload")

	// Open the local file.
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file %s for upload: %w", sanitizedFilePath, err)
	}
	// Ensure file is closed.
	defer func() {
		if err := file.Close(); err != nil {
			log.Warn().Err(err).Str("path", sanitizedFilePath).Msg("Failed to close file after S3 upload attempt")
		}
	}()

	// Get file size.
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", sanitizedFilePath, err)
	}
	fileSize := fileInfo.Size()
	log.Debug().Str("file", sanitizedFilePath).Int64("size_bytes", fileSize).Msg("File size determined")

	// Wrap the file reader with our counter for progress.
	reader := newReadCounter(file, sanitizedFilePath, fileSize)

	// Create uploader using the package variable (which can be mocked in tests)
	uploader := s3managerNewUploader(sess)

	// S3 key includes the optional prefix and the base file name.
	s3Key := filepath.Join(cfg.S3Prefix, filepath.Base(filePath))

	// --- Retry Block for Upload using custom retry --- //
	var uploadErr error

	uploadOperation := func(opCtx context.Context) error {
		// Need to reset the reader (seek to start) on each attempt
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			// Treat seek error as permanent for upload retries
			return fmt.Errorf("failed to seek file %s for retry: %w", sanitizedFilePath, err)
		}
		// Reset the read counter as well
		reader.total = 0
		reader.start = time.Now()

		log.Trace().Str("component", "s3").Str("file", sanitizedFilePath).Str("bucket", cfg.S3Bucket).Str("key", s3Key).Msg("Attempting S3 upload")

		_, err = uploader.UploadWithContext(opCtx, &s3manager.UploadInput{
			Bucket: aws.String(cfg.S3Bucket),
			Key:    aws.String(s3Key),
			Body:   reader,
		})
		// Return error to be checked by isTransientS3Error
		return err
	}

	// Execute the upload with retry
	uploadErr = retry.ExecuteWithRetry(ctx, defaultRetryConfig, uploadOperation, isTransientS3Error, "S3Upload")

	// --- End Retry Block --- //

	// Check the final error after retries
	if uploadErr != nil {
		log.Error().Err(uploadErr).Str("file", sanitizedFilePath).Str("bucket", cfg.S3Bucket).Str("key", s3Key).Msg("S3 upload failed after retries")
		return fmt.Errorf("failed to upload %s to s3://%s/%s: %w", sanitizedFilePath, cfg.S3Bucket, s3Key, uploadErr)
	}

	// Log final stats on success.
	duration := time.Since(reader.start)
	rate := float64(0)
	if duration.Seconds() > 0 {
		rate = float64(reader.total) / duration.Seconds()
	}
	log.Info().
		Str("component", "s3").
		Str("file", sanitizedFilePath).
		Str("bucket", cfg.S3Bucket).
		Str("key", s3Key).
		Int64("bytes_uploaded", reader.total).
		Dur("duration", duration).
		Str("rate", fmt.Sprintf("%.2f MiB/s", rate/1024/1024)).
		Msg("S3 upload successful")

	return nil
}

// DeleteOldSnapshotsFromS3 lists objects matching the snapshot prefix, identifies those older than the retention period,
// and deletes them using a batch delete operation.
func (c *Client) DeleteOldSnapshotsFromS3(ctx context.Context) error {
	// Create S3 client using the package variable (which can be mocked in tests)
	s3client := s3New(c.sess)

	log.Info().Str("component", "s3").Str("bucket", c.cfg.S3Bucket).Str("prefix", c.cfg.S3Prefix).Dur("retention", c.cfg.RetentionPeriod).Msg("Checking for old snapshots to delete")

	objectsToDelete := []*s3.ObjectIdentifier{}
	now := time.Now()
	cutoffTime := now.Add(-c.cfg.RetentionPeriod)

	// List objects with pagination
	listInput := &s3.ListObjectsV2Input{
		Bucket: aws.String(c.cfg.S3Bucket),
		Prefix: aws.String(c.cfg.S3Prefix),
	}

	err := s3client.ListObjectsV2PagesWithContext(ctx, listInput,
		func(page *s3.ListObjectsV2Output, lastPage bool) bool {
			for _, obj := range page.Contents {
				if obj.Key == nil || obj.LastModified == nil {
					log.Warn().Str("component", "s3").Interface("object", obj).Msg("Skipping object with nil key or last modified date")
					continue
				}

				// Only consider files ending with .sha256 to avoid deleting the snapshot before its checksum or vice versa
				if !strings.HasSuffix(*obj.Key, ".sha256") {
					continue
				}

				if obj.LastModified.Before(cutoffTime) {
					// Found an old checksum file, add it and its corresponding snapshot file to the delete list
					checksumKey := *obj.Key
					snapshotKey := strings.TrimSuffix(checksumKey, ".sha256")

					log.Debug().Str("checksum_file", checksumKey).Str("snapshot_file", snapshotKey).Time("last_modified", *obj.LastModified).Time("cutoff", cutoffTime).Msg("Marking old snapshot files for deletion")

					objectsToDelete = append(objectsToDelete, &s3.ObjectIdentifier{Key: aws.String(checksumKey)})
					objectsToDelete = append(objectsToDelete, &s3.ObjectIdentifier{Key: aws.String(snapshotKey)})
				}
			}
			// Continue pagination if needed (consider adding a limit or check context cancellation)
			select {
			case <-ctx.Done():
				log.Warn().Str("component", "s3").Msg("Context cancelled during S3 object listing")
				return false // Stop pagination
			default:
				return !lastPage // Continue if not the last page and context is not done
			}
		})

	if err != nil {
		// Check if the error is context cancellation
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("S3 object listing cancelled: %w", err)
		}
		// Check if it's a transient error that maybe should have been retried (though ListObjectsV2Pages usually handles some retries internally)
		if isTransientS3Error(err) {
			log.Error().Err(err).Msg("Transient error during S3 object listing pagination")
			return fmt.Errorf("transient error listing S3 objects: %w", err)
		}
		log.Error().Err(err).Msg("Permanent error during S3 object listing pagination")
		return fmt.Errorf("failed to list S3 objects: %w", err)
	}

	if len(objectsToDelete) == 0 {
		log.Info().Str("component", "s3").Str("bucket", c.cfg.S3Bucket).Str("prefix", c.cfg.S3Prefix).Msg("No old snapshots found to delete")
		return nil
	}

	log.Info().Str("component", "s3").Int("count", len(objectsToDelete)).Str("bucket", c.cfg.S3Bucket).Str("prefix", c.cfg.S3Prefix).Msg("Found old snapshots to delete")

	// Prepare the delete request.
	deleteInput := &s3.DeleteObjectsInput{
		Bucket: aws.String(c.cfg.S3Bucket),
		Delete: &s3.Delete{Objects: objectsToDelete},
	}

	// --- Retry Block for Delete using custom retry --- //
	var deleteErr error

	deleteOperation := func(opCtx context.Context) error {
		log.Trace().Str("component", "s3").Int("count", len(objectsToDelete)).Str("bucket", c.cfg.S3Bucket).Msg("Attempting batch delete")
		_, err := s3client.DeleteObjectsWithContext(opCtx, deleteInput)
		// Return error to be checked by isTransientS3Error
		return err
	}

	// Execute the delete with retry
	deleteErr = retry.ExecuteWithRetry(ctx, defaultRetryConfig, deleteOperation, isTransientS3Error, "S3Delete")

	// --- End Retry Block --- //

	// Check final error after retries
	if deleteErr != nil {
		log.Error().Err(deleteErr).Int("count", len(objectsToDelete)).Str("bucket", c.cfg.S3Bucket).Msg("S3 batch delete failed after retries")
		return fmt.Errorf("failed to delete old snapshots: %w", deleteErr)
	}

	log.Info().Str("component", "s3").Int("count", len(objectsToDelete)).Str("bucket", c.cfg.S3Bucket).Str("prefix", c.cfg.S3Prefix).Msg("Successfully deleted old snapshots")
	return nil
}
