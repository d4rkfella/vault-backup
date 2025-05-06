package vault

import (
	"context"
	"fmt"
	"time"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/kubernetes"
)

const DEFAULT_VAULT_NAMESPACE = "vault"

type Client struct {
	vaultClient  VaultAPI
	forceRestore bool
}

type Config struct {
	Address      string
	Token        string
	Namespace    string
	ForceRestore bool
	FileName     string
	Timeout      time.Duration
	CACert       string
	// Kubernetes auth config
	K8sAuthEnabled bool
	K8sAuthPath    string
	K8sTokenPath   string
	K8sRole        string
}

func NewClient(ctx context.Context, config *Config) (*Client, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = config.Address

	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Vault client: %w", err)
	}

	if config.CACert != "" {
		tlsConfig := &vault.TLSConfig{
			CACert: config.CACert,
		}
		err = vaultConfig.ConfigureTLS(tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
	}

	client.SetClientTimeout(config.Timeout)

	if config.Namespace != "" {
		client.SetNamespace(config.Namespace)
	}

	if config.K8sAuthEnabled {
		k8sAuth, err := auth.NewKubernetesAuth(
			config.K8sRole,
			auth.WithMountPath(config.K8sAuthPath),
			auth.WithServiceAccountTokenPath(config.K8sTokenPath),
		)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize Kubernetes auth method: %w", err)
		}

		authInfo, err := client.Auth().Login(timeoutCtx, k8sAuth)
		if err != nil {
			return nil, fmt.Errorf("unable to log in with Kubernetes auth: %w", err)
		}
		if authInfo == nil {
			return nil, fmt.Errorf("no auth info was returned after login")
		}
	} else {
		client.SetToken(config.Token)
	}

	if config.Namespace == "" {
		config.Namespace = DEFAULT_VAULT_NAMESPACE
	}
	client.SetNamespace(config.Namespace)

	return &Client{
		vaultClient:  &vaultAPIWrapper{client},
		forceRestore: config.ForceRestore,
	}, nil
}
