package vault

import (
	"context"
	"io"
)

func (c *Client) Restore(ctx context.Context, r io.Reader) error {
	err := c.vaultClient.Sys().RaftSnapshotRestoreWithContext(ctx, r, c.forceRestore)
	if err != nil {
		return err
	}
	return nil
}
