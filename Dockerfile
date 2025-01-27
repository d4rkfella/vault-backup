FROM python:alpine3.21@sha256:f9d772b2b40910ee8de2ac2b15ff740b5f26b37fc811f6ada28fce71a2542b0e AS builder

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


FROM alpine:3.21.2@sha256:56fa17d2a7e7f168a043a2712e63aed1f8543aeafdcee47c58dcffe38ed51099

LABEL maintainer="Georgi Panov"

USER root

COPY --from=hashicorp/vault:1.18@sha256:8f1ba670da547c6af67be55609bd285c3ee3d8b73f88021adbfc43c82ca409e8 /bin/vault /usr/local/bin/vault
COPY --from=builder /usr/local/aws-cli /usr/local/bin/aws

RUN apk update && apk add --no-cache \
    ca-certificates \
    bash \
    catatonit \
    aws --version && \
    vault --version

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

USER nobody:nogroup

ENTRYPOINT ["/usr/bin/catatonit", "--", "/entrypoint.sh"]
