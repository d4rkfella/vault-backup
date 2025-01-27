FROM python:alpine3.21@sha256:f9d772b2b40910ee8de2ac2b15ff740b5f26b37fc811f6ada28fce71a2542b0e

LABEL maintainer="Georgi Panov"

USER root
WORKDIR /tmp

COPY --from=hashicorp/vault:1.18@sha256:8f1ba670da547c6af67be55609bd285c3ee3d8b73f88021adbfc43c82ca409e8 /bin/vault /usr/local/bin/vault

RUN apk update && apk add --no-cache \
    curl \
    ca-certificates \
    bash \
    catatonit \
    unzip && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.22.35.zip" -o "awscliv2.zip" && unzip awscliv2.zip && ./aws/install && \
    rm -rf /tmp/* && \
    aws --version && \
    vault --version

WORKDIR /app

COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

USER nobody:nogroup

ENTRYPOINT ["/usr/bin/catatonit", "--", "/entrypoint.sh"]
