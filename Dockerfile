# Build stage
FROM rust:1.85-slim AS builder
WORKDIR /app

# Copy all source files
COPY . .

# Build the release binary for the server
RUN cargo build --release -p pq-aura-server

# Runtime stage
FROM debian:bookworm-slim
WORKDIR /app

# Install SSL certificates
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder
COPY --from=builder /app/target/release/pq-aura-server /app/pq-aura-server

# Set default port for Hugging Face Spaces (7860)
ENV PORT=7860
EXPOSE 7860
CMD ["/app/pq-aura-server"]
