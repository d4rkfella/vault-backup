FROM alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

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
