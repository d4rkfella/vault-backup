package app

import (
	"context"
	"fmt"
	"io"
	"time"
)

func Restore(ctx context.Context, vaultClient VaultClient, s3Client S3Client) (err error) {

	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	var objReader io.ReadCloser
	var fileName string

	fmt.Println("Starting restore...")

	fileName, err = s3Client.ResolveBackupKey(timeoutCtx)
	if err != nil {
		return err
	}

	objReader, err = s3Client.GetObject(timeoutCtx, fileName)
	if err != nil {
		return err
	}
	defer objReader.Close() //nolint:errcheck

	if err = vaultClient.Restore(timeoutCtx, objReader); err != nil {
		return err
	}

	fmt.Printf("Restored backup with name '%s'.\n", fileName)
	return nil
}
