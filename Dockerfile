FROM python:3.11-alpine3.21 AS builder

ARG AWS_CLI_VERSION=2.22.35

RUN apk add --no-cache git \
        unzip \
        groff \
        build-base \
        libffi-dev \
        cmake

RUN mkdir /aws && \
    git clone --single-branch --depth 1 -b ${AWS_CLI_VERSION} https://github.com/aws/aws-cli.git /aws && \
    cd /aws && \
    python -m venv venv && \
    . venv/bin/activate && \
    pip install --upgrade pip setuptools && \
    ./scripts/installers/make-exe

RUN unzip /aws/dist/awscli-exe.zip && \
    ./aws/install --bin-dir /aws-cli-bin

# Reduce image size: remove autocomplete and examples
RUN rm -rf \
    /usr/local/aws-cli/v2/current/dist/aws_completer \
    /usr/local/aws-cli/v2/current/dist/awscli/data/ac.index \
    /usr/local/aws-cli/v2/current/dist/awscli/examples && \
    find /usr/local/aws-cli/v2/current/dist/awscli/data -name completions-1*.json -delete && \
    find /usr/local/aws-cli/v2/current/dist/awscli/botocore/data -name examples-1.json -delete


FROM alpine:3.21

USER root

COPY --from=hashicorp/vault:1.18 /bin/vault /usr/local/bin/vault
RUN vault --version

COPY --from=builder /usr/local/aws-cli /usr/local/aws-cli
COPY --from=builder /aws-cli-bin/ /usr/local/bin/
RUN aws --version

RUN apk update && apk add --no-cache \
    ca-certificates \
    bash \
    catatonit

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER nobody:nogroup

ENTRYPOINT ["/usr/bin/catatonit", "--", "/entrypoint.sh"]

LABEL org.opencontainers.image.source="https://github.com/hashicorp/vault"
LABEL org.opencontainers.image.title="vault-backup"
LABEL org.opencontainers.image.authors="Georgi Panov"
