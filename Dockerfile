FROM ubuntu:25.04

LABEL maintainer="Georgi Panov"

ARG VAULT_VERSION="1.18.3"

RUN groupadd -g 65532 appuser \
    && useradd -m -r -u 65532 -g appuser appuser \
    && apt update -y && apt install -y gnupg wget curl zip unzip \
    && wget https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip && unzip vault_${VAULT_VERSION}_linux_amd64.zip && mv vault /usr/local/bin \
    && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.22.35.zip" -o "awscliv2.zip" && unzip awscliv2.zip && ./aws/install

WORKDIR /app

COPY backupVault.sh /app/backupVault.sh
RUN chmod +x /app/backupVault.sh

USER appuser
WORKDIR /app

CMD  ["./backupVault.sh" ]
