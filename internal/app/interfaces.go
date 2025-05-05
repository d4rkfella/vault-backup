package app

import (
	"context"
	"io"
	"time"
)

type VaultClient interface {
	Backup(ctx context.Context, w io.Writer) error
	Restore(ctx context.Context, r io.Reader) error
	RevokeToken(ctx context.Context) error
}

type S3Client interface {
	PutObject(ctx context.Context, key string, r io.Reader) error
	GetObject(ctx context.Context, key string) (io.ReadCloser, error)
	HeadObject(ctx context.Context, key string) (bool, error)
	FindLatestSnapshotKey(ctx context.Context) (string, error)
}

type NotifyClient interface {
	Notify(ctx context.Context, success bool, opType string, duration time.Duration, sizeBytes int64, err error, details map[string]string) error
}
