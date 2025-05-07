package vault

import (
	"context"
	"io"

	vault "github.com/hashicorp/vault/api"
)

type AuthAPI interface {
	Login(ctx context.Context, authMethod vault.AuthMethod) (*vault.Secret, error)
}

type SysAPI interface {
	RaftSnapshotWithContext(ctx context.Context, w io.Writer) error
	RaftSnapshotRestoreWithContext(ctx context.Context, r io.Reader, force bool) error
}

type VaultAPI interface {
	Sys() SysAPI
	Auth() AuthAPI
	SetNamespace(namespace string)
	Token() string
}

type vaultAPIWrapper struct {
	*vault.Client
}

func (w *vaultAPIWrapper) Sys() SysAPI   { return w.Client.Sys() }
func (w *vaultAPIWrapper) Auth() AuthAPI { return w.Client.Auth() }

var _ VaultAPI = (*vaultAPIWrapper)(nil)

var _ AuthAPI = (*vault.Auth)(nil)
var _ SysAPI = (*vault.Sys)(nil)
