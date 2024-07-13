FROM rust:alpine as builder
WORKDIR /app
COPY . .
RUN apk add --no-cache musl-dev gcc && \
    rustup target add x86_64-unknown-linux-musl && \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc cargo build --target x86_64-unknown-linux-musl --release

FROM alpine:3
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/rustyalias /usr/local/bin/rustyalias
EXPOSE 5053/udp
ENV RUST_LOG=info
USER nobody:nobody
CMD ["/usr/local/bin/rustyalias"]