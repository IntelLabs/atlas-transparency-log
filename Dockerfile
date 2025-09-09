FROM rust:1.89 as builder
WORKDIR /usr/src/app
COPY . .
RUN cargo build --release

FROM debian:trixie-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

COPY --from=builder /usr/src/app/target/release/atlas-transparency-log /usr/local/bin/atlas-transparency-log
RUN chmod +x /usr/local/bin/atlas-transparency-log

# Switch to non-root user
USER appuser

EXPOSE 8080
CMD ["atlas-transparency-log"]