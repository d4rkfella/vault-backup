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

*(Add instructions here if you plan to distribute binaries, e.g., via GitHub Releases or a package manager.)*

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

| Flag                       | Environment Variable         | Config Key               | Default                                                 | Description                                                                 |
| :------------------------- | :--------------------------- | :----------------------- | :------------------------------------------------------ | :-------------------------------------------------------------------------- |
| `--config`                 | `CONFIG`                     | `config`                 | `""`                                                     | Path to the configuration file.                                               |
| **Vault**                  |                              |                          |                                                         |                                                                             |
| `-a`, `--vault-address`    | `VAULT_ADDRESS`              | `vault_address`          | `http://localhost:8200`                                 | Vault server address.                                                       |
| `-n`, `--vault-namespace`  | `VAULT_NAMESPACE`            | `vault_namespace`        | `""`                                                     | Vault namespace (if used).                                                  |
| `-t`, `--vault-token`      | `VAULT_TOKEN`                | `vault_token`            | `""`                                                     | Vault token for authentication. **Required** if K8s auth is not enabled.    |
| `--vault-timeout`          | `VAULT_TIMEOUT`              | `vault_timeout`          | `30s`                                                   | Timeout for Vault client operations.                                        |
| `--vault-ca-cert`          | `VAULT_CA_CERT`              | `vault_ca_cert`          | `""`                                                     | Path to a custom CA certificate file for Vault connection.                  |
| `--vault-k8s-auth-enabled` | `VAULT_K8S_AUTH_ENABLED`     | `vault_k8s_auth_enabled` | `false`                                                 | Enable Kubernetes authentication. **Required** if Vault token is not set. |
| `--vault-k8s-auth-path`    | `VAULT_K8S_AUTH_PATH`        | `vault_k8s_auth_path`    | `kubernetes`                                            | Mount path for the Kubernetes auth method in Vault.                       |
| `--vault-k8s-token-path`   | `VAULT_K8S_TOKEN_PATH`       | `vault_k8s_token_path`   | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Path to the Kubernetes service account token file inside the pod.           |
| `--vault-k8s-role`         | `VAULT_K8S_ROLE`             | `vault_k8s_role`         | `""`                                                     | Vault role to use for Kubernetes authentication. **Required** if K8s enabled. |
| **S3 Storage**             |                              |                          |                                                         |                                                                             |
| `--s3-access-key`          | `S3_ACCESS_KEY`              | `s3_access_key`          | `""`                                                     | S3 access key. **Required**.                                                |
| `--s3-secret-key`          | `S3_SECRET_KEY`              | `s3_secret_key`          | `""`                                                     | S3 secret key. **Required**.                                                |
| `--s3-bucket`              | `S3_BUCKET`                  | `s3_bucket`              | `""`                                                     | S3 bucket name. **Required**.                                               |
| `--s3-region`              | `S3_REGION`                  | `s3_region`              | `us-east-1`                                             | S3 region.                                                                  |
| `--s3-endpoint`            | `S3_ENDPOINT`                | `s3_endpoint`            | `""`                                                     | Custom S3 endpoint URL (for S3-compatible storage like MinIO).            |
| `--s3-filename`            | `S3_FILENAME`                | `s3_filename`            | `""`                                                     | Specific S3 filename to restore (optional, defaults to latest `.snap`).   |
| **Notifications**          |                              |                          |                                                         |                                                                             |
| `--pushover-api-key`       | `PUSHOVER_API_KEY`           | `pushover_api_key`       | `""`                                                     | Pushover application API key/token. (Optional, requires user key too).    |
| `--pushover-user-key`      | `PUSHOVER_USER_KEY`          | `pushover_user_key`      | `""`                                                     | Pushover user/group key. (Optional, requires API key too).              |

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