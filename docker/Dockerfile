FROM rust:1.85-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build -p mcp-firewall --release

FROM debian:bookworm-slim
RUN useradd -m -u 10001 app
WORKDIR /home/app
COPY --from=builder /app/target/release/mcp-firewall /usr/local/bin/mcp-firewall
USER app
ENTRYPOINT ["mcp-firewall"]
