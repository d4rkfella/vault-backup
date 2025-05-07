package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
)

type mockVaultAPI struct {
	SysFunc          func() SysAPI
	AuthFunc         func() AuthAPI
	SetNamespaceFunc func(namespace string)
	TokenFunc        func() string

	setNamespaceCalledWith string
}

func (m *mockVaultAPI) Sys() SysAPI {
	if m.SysFunc != nil {
		return m.SysFunc()
	}
	return &mockSysAPI{}
}

func (m *mockVaultAPI) Auth() AuthAPI {
	if m.AuthFunc != nil {
		return m.AuthFunc()
	}
	return &mockAuthAPI{}
}

func (m *mockVaultAPI) SetNamespace(namespace string) {
	m.setNamespaceCalledWith = namespace
	if m.SetNamespaceFunc != nil {
		m.SetNamespaceFunc(namespace)
	}
}

func (m *mockVaultAPI) Token() string {
	if m.TokenFunc != nil {
		return m.TokenFunc()
	}
	return "mock-token"
}

// --- Mock SysAPI ---
type mockSysAPI struct {
	RaftSnapshotFunc        func(ctx context.Context, w io.Writer) error
	RaftSnapshotRestoreFunc func(ctx context.Context, r io.Reader, force bool) error
}

func (m *mockSysAPI) RaftSnapshotWithContext(ctx context.Context, w io.Writer) error {
	if m.RaftSnapshotFunc != nil {
		return m.RaftSnapshotFunc(ctx, w)
	}
	return nil
}

func (m *mockSysAPI) RaftSnapshotRestoreWithContext(ctx context.Context, r io.Reader, force bool) error {
	if m.RaftSnapshotRestoreFunc != nil {
		return m.RaftSnapshotRestoreFunc(ctx, r, force)
	}
	return nil
}

type mockAuthAPI struct {
	LoginFunc func(ctx context.Context, authMethod vault.AuthMethod) (*vault.Secret, error)
}

func (m *mockAuthAPI) Login(ctx context.Context, authMethod vault.AuthMethod) (*vault.Secret, error) {
	if m.LoginFunc != nil {
		return m.LoginFunc(ctx, authMethod)
	}
	return &vault.Secret{Auth: &vault.SecretAuth{ClientToken: "mock-k8s-token-from-default-login"}}, nil 
}

func newTestConfig() *Config {
	return &Config{
		Address: "http://localhost:8200",
		Token:   "test-token",
		Timeout: 10 * time.Second,
	}
}

var originalVaultNewClientFunc = vaultNewClientFunc

func TestNewClient(t *testing.T) {
	defer func() { vaultNewClientFunc = originalVaultNewClientFunc }()

	ctx := context.Background()

	t.Run("successful token auth", func(t *testing.T) {
		cfg := newTestConfig()
		
		var returnedClient *vault.Client
		vaultNewClientFunc = func(c *vault.Config) (*vault.Client, error) {
			vc, err := originalVaultNewClientFunc(c)
			if err != nil { 
				// This shouldn't happen in the test if address is valid, but good to propagate
				return nil, fmt.Errorf("originalVaultNewClientFunc failed: %w", err)
			}
			returnedClient = vc
			return vc, nil
		}

		client, err := NewClient(ctx, cfg)
		if err != nil {
			t.Fatalf("NewClient() with token auth error = %v, want nil", err)
		}
		if client == nil {
			t.Fatal("NewClient() returned nil client")
		}
		if client.vaultClient == nil {
			t.Fatal("client.vaultClient is nil")
		}
		
		if returnedClient == nil {
		    t.Fatal("vaultNewClientFunc did not return a client to check")
		}
		if returnedClient.Token() != cfg.Token {
		    t.Errorf("Expected token %q to be set on underlying client, got %q", cfg.Token, returnedClient.Token())
		}
		if returnedClient.Namespace() != DEFAULT_VAULT_NAMESPACE {
		    t.Errorf("Expected namespace %q, got %q", DEFAULT_VAULT_NAMESPACE, returnedClient.Namespace())
		}
		if client.forceRestore != cfg.ForceRestore {
			t.Errorf("client.forceRestore = %v, want %v", client.forceRestore, cfg.ForceRestore)
		}
	})

	t.Run("error from vaultNewClientFunc", func(t *testing.T) {
		cfg := newTestConfig()
		expectedErr := fmt.Errorf("new client creation failed")
		vaultNewClientFunc = func(c *vault.Config) (*vault.Client, error) {
			return nil, expectedErr
		}
		_, err := NewClient(ctx, cfg)
		if err == nil {
			t.Fatal("NewClient() error = nil, want error")
		}
		if !strings.Contains(err.Error(), expectedErr.Error()) {
			t.Errorf("NewClient() error = %v, want to contain %v", err, expectedErr)
		}
	})
}

func TestClient_Backup(t *testing.T) {
	ctx := context.Background()
	var writerBuf bytes.Buffer

	t.Run("successful backup", func(t *testing.T) {
		mockSys := &mockSysAPI{}
		mockVault := &mockVaultAPI{}
		mockVault.SysFunc = func() SysAPI { return mockSys } // Connect Sys() to our mock

		client := &Client{
			vaultClient: mockVault,
			// forceRestore doesn't affect Backup
		}

		var snapshotCalled bool
		mockSys.RaftSnapshotFunc = func(ctx context.Context, w io.Writer) error {
			snapshotCalled = true
			// Simulate writing some data
			_, err := w.Write([]byte("raft-snapshot-data"))
			return err
		}

		err := client.Backup(ctx, &writerBuf)
		if err != nil {
			t.Fatalf("Backup() error = %v, want nil", err)
		}
		if !snapshotCalled {
			t.Error("Expected RaftSnapshotWithContext to be called, but it wasn't")
		}
		if writerBuf.String() != "raft-snapshot-data" {
			t.Errorf("Backup() wrote %q, want %q", writerBuf.String(), "raft-snapshot-data")
		}
		writerBuf.Reset() // Reset buffer for next test
	})

	t.Run("snapshot returns error", func(t *testing.T) {
		mockSys := &mockSysAPI{}
		mockVault := &mockVaultAPI{}
		mockVault.SysFunc = func() SysAPI { return mockSys }

		client := &Client{
			vaultClient: mockVault,
		}

		expectedErr := fmt.Errorf("raft snapshot failed")
		mockSys.RaftSnapshotFunc = func(ctx context.Context, w io.Writer) error {
			return expectedErr
		}

		err := client.Backup(ctx, &writerBuf)
		if err == nil {
			t.Fatal("Backup() error = nil, want error")
		}
		if !errors.Is(err, expectedErr) { // Use errors.Is for potential wrapping
			t.Errorf("Backup() error = %v, want %v", err, expectedErr)
		}
		writerBuf.Reset()
	})
}

func TestClient_Restore(t *testing.T) {
	ctx := context.Background()
	testBodyContent := "this is restore data"
	
	tests := []struct {
		name           string
		forceRestore   bool // Value for client.forceRestore
		simulateError  error // Error to return from mock, nil for success
		wantErr        bool
		expectedForce  bool // Expected force flag passed to RaftSnapshotRestoreWithContext
	}{
		{
			name:          "successful restore (force=false)",
			forceRestore:  false,
			simulateError: nil,
			wantErr:       false,
			expectedForce: false,
		},
		{
			name:          "successful restore (force=true)",
			forceRestore:  true,
			simulateError: nil,
			wantErr:       false,
			expectedForce: true,
		},
		{
			name:          "restore returns error (force=false)",
			forceRestore:  false,
			simulateError: fmt.Errorf("raft restore failed"),
			wantErr:       true,
			expectedForce: false,
		},
		{
			name:          "restore returns error (force=true)",
			forceRestore:  true,
			simulateError: fmt.Errorf("raft restore failed with force"),
			wantErr:       true,
			expectedForce: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSys := &mockSysAPI{}
			mockVault := &mockVaultAPI{}
			mockVault.SysFunc = func() SysAPI { return mockSys } 

			client := &Client{
				vaultClient:  mockVault,
				forceRestore: tt.forceRestore,
			}

			var restoreCalled bool
			var forcePassed bool
			mockSys.RaftSnapshotRestoreFunc = func(ctx context.Context, r io.Reader, force bool) error {
				restoreCalled = true
				forcePassed = force
				// Consume reader to simulate action
				_, _ = io.ReadAll(r)
				return tt.simulateError
			}

			reader := strings.NewReader(testBodyContent)
			err := client.Restore(ctx, reader)

			if (err != nil) != tt.wantErr {
				t.Errorf("Restore() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, tt.simulateError) {
				t.Errorf("Restore() error = %v, want %v", err, tt.simulateError)
			}

			if !restoreCalled {
				t.Error("Expected RaftSnapshotRestoreWithContext to be called, but it wasn't")
			} else {
				if forcePassed != tt.expectedForce {
					t.Errorf("RaftSnapshotRestoreWithContext called with force=%v, want %v", forcePassed, tt.expectedForce)
				}
			}
		})
	}
} 