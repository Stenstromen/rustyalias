FROM rust:alpine AS builder
ARG TARGETARCH
WORKDIR /app
COPY . .
RUN apk add --no-cache musl-dev gcc && \
    case "$TARGETARCH" in \
      amd64) RUST_TARGET="x86_64-unknown-linux-musl" ;; \
      arm64) RUST_TARGET="aarch64-unknown-linux-musl" ;; \
      *) echo "Unsupported architecture: $TARGETARCH" && exit 1 ;; \
    esac && \
    rustup target add "$RUST_TARGET" && \
    cargo build --target "$RUST_TARGET" --release && \
    cp "target/$RUST_TARGET/release/rustyalias" /rustyalias

FROM scratch
COPY --from=builder /rustyalias /rustyalias
EXPOSE 5053/udp
EXPOSE 5053/tcp
ENV RUST_LOG=info
USER 65534:65534
CMD ["/rustyalias"]
