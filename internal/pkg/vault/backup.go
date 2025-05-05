package vault

import (
	"context"
	"io"
)

func (c *Client) Backup(ctx context.Context, w io.Writer) error {
	return c.vaultClient.Sys().RaftSnapshotWithContext(ctx, w)
}
