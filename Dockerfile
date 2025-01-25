FROM ubuntu:25.04

LABEL maintainer="Georgi Panov"

COPY --from=hashicorp/vault:1.18@sha256:8f1ba670da547c6af67be55609bd285c3ee3d8b73f88021adbfc43c82ca409e8 /bin/vault /usr/local/bin/vault
COPY --from=amazon/aws-cli:2.22.35@sha256:6977c83ae3dc99f28fcf8276b9ea5eec33833cd5be40574b34112e98113ec7a2 /usr/local/bin/aws /usr/local/bin/aws

RUN groupadd -g 999 appuser \
    && useradd -m -r -u 999 -g appuser appuser

WORKDIR /app

COPY backupVault.sh /app/backupVault.sh
RUN chmod +x /app/backupVault.sh

USER appuser
WORKDIR /app

CMD  ["./backupVault.sh" ]
