FROM alpine:3.21.3

COPY --from=hashicorp/vault:1.19.0 /bin/vault /usr/local/bin/vault
RUN vault --version

COPY --from=ghcr.io/d4rkfella/aws-cli-alpine:2.22.35 /usr/local/aws-cli/ /usr/local/aws-cli/
COPY --from=ghcr.io/d4rkfella/aws-cli-alpine:2.22.35 /aws-cli-bin/ /usr/local/bin/

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
