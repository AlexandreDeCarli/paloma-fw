# Stage 1: Build the static Go binary
FROM golang:alpine AS builder

WORKDIR /app

# Download dependencies first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY . .

# Build stripped static binary
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o paloma-fw .

# Stage 2: Ultra-lightweight runtime container
FROM alpine:3.21

# Install fail2ban client so the container can interact with the host socket
RUN apk add --no-cache ca-certificates tzdata fail2ban curl

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/paloma-fw /app/paloma-fw

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3340/healthz || exit 1

EXPOSE 3340

CMD ["/app/paloma-fw"]
