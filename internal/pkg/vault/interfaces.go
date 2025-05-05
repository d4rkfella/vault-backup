package vault

import (
	"context"
	"io"

	vault "github.com/hashicorp/vault/api"
)

type TokenAPI interface {
	RevokeSelfWithContext(ctx context.Context, token string) error
}

type AuthAPI interface {
	Token() TokenAPI
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
func (w *vaultAPIWrapper) Auth() AuthAPI { return &authAPIWrapper{w.Client.Auth()} }

var _ VaultAPI = (*vaultAPIWrapper)(nil)

type authAPIWrapper struct {
	*vault.Auth
}

func (w *authAPIWrapper) Token() TokenAPI { return w.Auth.Token() }

var _ AuthAPI = (*authAPIWrapper)(nil)

var _ TokenAPI = (*vault.TokenAuth)(nil)
var _ SysAPI = (*vault.Sys)(nil)
