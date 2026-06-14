# --- Builder Stage ---
FROM alpine:latest AS builder

# Install dependencies for downloading and extracting
RUN apk add --no-cache curl tar

# Define Gitleaks version
ARG GITLEAKS_VERSION=8.18.2

# Download the correct architecture binary
RUN set -x && \
    ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
        GITLEAKS_ARCH="x64"; \
    elif [ "$ARCH" = "aarch64" ]; then \
        GITLEAKS_ARCH="arm64"; \
    else \
        echo "Unsupported architecture: $ARCH" && exit 1; \
    fi && \
    curl -L -o gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" && \
    tar -xzf gitleaks.tar.gz gitleaks

# --- Runtime Stage ---
FROM python:3.12-slim

# Git is required for GitSin's blame and telemetry modules
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Copy gitleaks binary from the builder stage
COPY --from=builder /gitleaks /usr/local/bin/gitleaks
RUN chmod +x /usr/local/bin/gitleaks

# Set up the working directory
WORKDIR /app

# Install uv for lightning-fast python dependencies
RUN pip install --no-cache-dir uv

# Copy the project files
COPY pyproject.toml README.md ./
COPY gitsin/ ./gitsin/

# Install the application
RUN uv pip install --system .

# GitSin operates as a native CLI inside the container
ENTRYPOINT ["gitsin"]
CMD ["--help"]
