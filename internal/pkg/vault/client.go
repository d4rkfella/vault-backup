package vault

import (
	"context"
	"time"

	"github.com/hashicorp/vault/api"
)

const DEFAULT_VAULT_NAMESPACE = "vault"

type Client struct {
	vaultClient  *vault.Client
	forceRestore bool
}

type Config struct {
	Address      string
	Token        string
	Namespace    string
	ForceRestore bool
	TmpPath      string
	FileName     string
	Timeout      time.Duration
	// Kubernetes auth config
	K8sAuthEnabled bool
	K8sAuthPath    string
	K8sRole        string
	K8sJWT         string
}

func NewClient(ctx context.Context, config Config) (*Client, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = config.Address

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}

	if config.Namespace != "" {
		client.SetNamespace(config.Namespace)
	}

	if config.K8sAuthEnabled {
		authData := map[string]interface{}{
			"role": config.K8sRole,
			"jwt":  config.K8sJWT,
		}

		secret, err := client.Logical().WriteWithContext(timeoutCtx, config.K8sAuthPath+"/login", authData)
		if err != nil {
			return nil, err
		}

		client.SetToken(secret.Auth.ClientToken)
	} else if config.Token != "" {
		client.SetToken(config.Token)
	}

	if config.Namespace == "" {
		config.Namespace = DEFAULT_VAULT_NAMESPACE
	}

	client.SetNamespace(config.Namespace)

	return &Client{
		vaultClient:  client,
		forceRestore: config.ForceRestore,
	}, nil
}
