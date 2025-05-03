package vault

import (
	"context"
	"io"
)

func (v *Client) Backup(ctx context.Context, w io.Writer) error {
	err := v.vaultClient.Sys().RaftSnapshotWithContext(ctx, w)
	if err != nil {
		return err
	}

	return nil
}
