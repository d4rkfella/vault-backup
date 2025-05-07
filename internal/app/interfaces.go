package app

import (
	"context"
	"io"
)

type VaultClient interface {
	Backup(ctx context.Context, w io.Writer) error
	Restore(ctx context.Context, r io.Reader) error
}

type S3Client interface {
	PutObject(ctx context.Context, key string, r io.Reader) error
	GetObject(ctx context.Context, key string) (body io.ReadCloser, err error)
	ResolveBackupKey(ctx context.Context) (string, error)
}
