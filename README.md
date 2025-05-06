# Vault Backup CLI

`vault-backup` is a command-line tool to backup and restore HashiCorp Vault data using Vault's integrated storage (Raft) snapshots. It interacts with Vault's API to trigger snapshots and can store/retrieve these snapshots from an S3-compatible object storage service.

## Features

*   **Backup:** Takes a Raft snapshot from Vault and uploads it to S3.
*   **Restore:** Retrieves a specified snapshot (or the latest) from S3 and restores it to Vault.
*   **S3 Integration:** Uses AWS S3 or any S3-compatible storage (MinIO, Ceph, etc.).
*   **Authentication:** Supports Vault token and Kubernetes authentication.
*   **Notifications:** Can send success/failure notifications via Pushover.
*   **Configuration:** Flexible configuration via command-line flags, environment variables, or a configuration file.

## Installation

You can download pre-built binaries for your operating system from the [GitHub Releases](https://github.com/d4rkfella/vault-backup/releases/) page.

Alternatively, you can build from source:

1.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd vault-backup
    ```
2.  **Build the binary:**
    ```bash
    go build -o vault-backup main.go
    ```
    This will create the `vault-backup` executable in the current directory.

## Usage

```
 vault-backup [command]
```

**Available Commands:**

*   `backup`: Perform a Vault backup and store the snapshot in S3.
*   `restore`: Restore a Vault backup from an S3 snapshot.
*   `help`: Display help information.
*   `version`: Show the application version.

Use `vault-backup [command] --help` for more information about a specific command.

### Backup Command

```bash
vault-backup backup [flags]
```

Triggers a Vault Raft snapshot and uploads it to the configured S3 bucket. The filename in S3 will be `raft_snapshot-<timestamp>.snap`.

### Restore Command

```bash
vault-backup restore [flags]
```

Restores a Vault Raft snapshot from S3. By default, it finds the *latest* `.snap` file in the bucket. You can specify a particular snapshot file using the `--s3-filename` flag.

**Important:** The restore operation is destructive and replaces the current Vault data. Use with caution.

**Flags:**

*   `--force`, `-f`: Force the restore operation without prompting (Use with extreme caution!).

## Configuration

Configuration can be provided through three methods (in order of precedence: Flags > Environment Variables > Config File):

1.  **Command-line Flags:** Pass flags directly (e.g., `--vault-token=...`).
2.  **Environment Variables:** Set environment variables corresponding to the flags (e.g., `VAULT_TOKEN=...`). Underscores replace hyphens, and the name is uppercased.
3.  **Configuration File:** Create a YAML file (default: `$HOME/.vault-backup.yaml`) with keys matching the flag names (with underscores instead of hyphens).

**Example Config File (`~/.vault-backup.yaml`):**

```yaml
vault_address: http://127.0.0.1:8200
vault_token: hvs.YOUR_VAULT_TOKEN
# vault_k8s_auth_enabled: true
# vault_k8s_role: your-k8s-role
s3_access_key: YOUR_S3_ACCESS_KEY
s3_secret_key: YOUR_S3_SECRET_KEY
s3_bucket: your-vault-backups-bucket
s3_region: us-east-1
# s3_endpoint: http://minio.local:9000 # Optional: for S3-compatible storage
pushover_api_key: YOUR_PUSHOVER_APP_TOKEN # Optional
pushover_user_key: YOUR_PUSHOVER_USER_KEY # Optional
```

### Configuration Options

| Variable          | Flag                           | Description                                           | Required                               | Default                                                 |
| :---------------- | :----------------------------- | :---------------------------------------------------- | :------------------------------------- | :------------------------------------------------------ |
| `cfgFile`         | `--config`                     | config file                                           | No                                     | `$HOME/.vault-backup.yaml`                              |
| **Vault**         |                                |                                                       |                                        |                                                         |
| `vaultAddr`       | `-a`, `--vault-address`        | Vault server address                                  | No                                     | `http://localhost:8200`                                 |
| `vaultNamespace`  | `-n`, `--vault-namespace`      | Vault namespace                                       | No                                     | `""`                                                    |
| `vaultToken`      | `-t`, `--vault-token`          | Vault token                                           | Yes (if K8s auth not enabled)          | `""`                                                    |
| `vaultTimeout`    | `--vault-timeout`              | Vault client timeout                                  | No                                     | `30s`                                                   |
| `vaultCACert`     | `--vault-ca-cert`              | Path to the Vault CA certificate file                 | No                                     | `""`                                                    |
| `k8sAuthEnabled`  | `--vault-k8s-auth-enabled`     | Enable Kubernetes authentication                      | Yes (if Vault token not set)           | `false`                                                 |
| `k8sAuthPath`     | `--vault-k8s-auth-path`        | Kubernetes auth mount path                            | No                                     | `kubernetes`                                            |
| `k8sTokenPath`    | `--vault-k8s-token-path`       | Kubernetes service account token mount path           | No                                     | `/var/run/secrets/kubernetes.io/serviceaccount/token` |
| `k8sRole`         | `--vault-k8s-role`             | Kubernetes role for authentication                    | Yes (if K8s auth enabled)              | `""`                                                    |
| **S3 Storage**    |                                |                                                       |                                        |                                                         |
| `S3_ACCESS_KEY`     | `--s3-access-key`              | S3 access key                                         | Yes                                    | `""`                                                    |
| `S3_SECRET_KEY`     | `--s3-secret-key`              | S3 secret key                                         | Yes                                    | `""`                                                    |
| `S3_BUCKET`        | `--s3-bucket`                  | S3 bucket name                                        | Yes                                    | `""`                                                    |
| `S3_REGION`        | `--s3-region`                  | S3 region                                             | No                                     | `us-east-1`                                             |
| `S3_ENDPOINT`      | `--s3-endpoint`                | S3 endpoint URL (for S3-compatible storage)           | No                                     | `""`                                                    |
| `S3_FILENAME`      | `--s3-filename`                | Specific S3 filename (used only for restore)          | No                                     | `""`                                                    |
| **Notifications** |                                |                                                       |                                        |                                                         |
| `PUSHOVER_API_KEY`  | `--pushover-api-key`           | Pushover API key                                      | No (but requires user key if set)    | `""`                                                    |
| `PUSHOVER_USER_KEY` | `--pushover-user-key`          | Pushover user key                                     | No (but requires API key if set)     | `""`                                                    |
| **Restore**       |                                |                                                       |                                        |                                                         |
| `FORCE`    | `-f`, `--force`                | Force restore operation (restore command only)        | No                                     | `false`                                                 |

**Required Configuration:**

*   S3 Access Key, Secret Key, and Bucket Name must always be provided.
*   Either a Vault Token OR Kubernetes Authentication (Enabled + Role) must be provided.

## Development

*(Add details about setting up a development environment, running tests, etc.)*

```bash
go test ./...
```

## Contributing

*(Add contribution guidelines if desired.)*

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
