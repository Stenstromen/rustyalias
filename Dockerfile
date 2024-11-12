FROM rust:alpine as builder
WORKDIR /app
COPY . .
RUN apk add --no-cache musl-dev gcc && \
    rustup target add x86_64-unknown-linux-musl && \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=gcc cargo build --target x86_64-unknown-linux-musl --release

FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/rustyalias /rustyalias
EXPOSE 5053/udp
EXPOSE 5053/tcp
ENV RUST_LOG=info
USER 65534:65534
CMD ["/rustyalias"]