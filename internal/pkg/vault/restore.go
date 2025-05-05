package vault

import (
	"context"
	"io"
)

func (c *Client) Restore(ctx context.Context, r io.Reader) error {
	return c.vaultClient.Sys().RaftSnapshotRestoreWithContext(ctx, r, c.forceRestore)
}
