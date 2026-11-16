# frasil-relay, the always-on peer service (apps/relay), as a container image.
#
#   docker build -f packaging/server/Dockerfile -t frasil-relay .
#
# Every extension is built in. The operator turns each on when the peer
# starts, with FRASIL_EXTENSIONS, such as
# `docker run -e FRASIL_EXTENSIONS="libraries deposit-tokens ephemeral invite-links" frasil-relay`;
# libraries and deposit-tokens are on by default. See docs/self-hosting.md.
FROM rust:1.96.1-slim-bookworm AS builder
ENV RUSTUP_TOOLCHAIN=1.96.1
WORKDIR /workspace
COPY . .
RUN cargo build --release --locked --package frasil-relay --bin frasil-relay

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 frasil-relay \
    && useradd --uid 10001 --gid frasil-relay --no-create-home frasil-relay \
    && mkdir /data && chown frasil-relay:frasil-relay /data
COPY --from=builder /workspace/target/release/frasil-relay /usr/local/bin/frasil-relay
# The database, the iroh key, the operator key and, unless a bucket holds
# them, the object chunks live in /data. HTTP on 8787 behind the operator's TLS proxy; the
# iroh binding on UDP 8788.
ENV FRASIL_DATA_DIR=/data FRASIL_LISTEN=0.0.0.0:8787 FRASIL_IROH_BIND=0.0.0.0:8788
EXPOSE 8787/tcp 8788/udp
USER frasil-relay
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD curl --fail --silent http://127.0.0.1:8787/healthz > /dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/frasil-relay"]
CMD ["serve"]
