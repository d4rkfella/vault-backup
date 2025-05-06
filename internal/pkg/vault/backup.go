package vault

import (
	"context"
	"io"
)

func (c *Client) Backup(ctx context.Context, w io.Writer) error {
	err := c.vaultClient.Sys().RaftSnapshotWithContext(ctx, w)
	if err != nil {
		return err
	}
	return nil
}
