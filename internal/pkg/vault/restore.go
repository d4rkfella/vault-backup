package vault

import (
	"context"
	"io"
)

func (c *Client) Restore(ctx context.Context, r io.Reader) error {
	if !c.forceRestore {
		return ErrForceRestoreRequired
	}
	return c.vaultClient.Sys().RaftSnapshotRestoreWithContext(ctx, r, true)
}

var ErrForceRestoreRequired = errors.New("force restore is required but not enabled")
