# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Install build dependencies for SQLite
RUN apk add --no-cache gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with CGO enabled for SQLite
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-linkmode external -extldflags '-static'" -o server ./cmd/server

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk --no-cache add ca-certificates sqlite-libs su-exec

# Create non-root user
RUN adduser -D -u 1000 secushare

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/server .
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Create storage directory and set permissions
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && mkdir -p /app/data /app/storage \
    && chown -R secushare:secushare /app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["./server"]
