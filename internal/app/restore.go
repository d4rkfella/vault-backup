package app

import (
	"context"
	"fmt"
	"io"
)

func Restore(ctx context.Context, vaultClient VaultClient, s3Client S3Client) error {
	var err error
	var objReader io.ReadCloser
	var fileName string

	fmt.Println("Starting restore...")

	fileName, err = s3Client.ResolveBackupKey(ctx)
	if err != nil {
		return err
	}

	objReader, err = s3Client.GetObject(ctx, fileName)
	if err != nil {
		return err
	}
	defer objReader.Close()

	if err = vaultClient.Restore(ctx, objReader); err != nil {
		return err
	}

	fmt.Printf("Restored backup with name '%s'.\n", fileName)
	return nil
}
