FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG BUILD_VERSION=dev

WORKDIR /app

# Copy source code first so 'go mod tidy' knows what to fetch
COPY . .
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags "-X main.scannerVersion=$BUILD_VERSION" \
    -o scanner .

FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache nmap nmap-scripts sqlite-libs

WORKDIR /app
COPY --from=builder /app/scanner .

# Ensure DB is persistent via volume mount to /app/data
ENV DB_PATH=/app/data/scanner.db
RUN mkdir -p /app/data

ENTRYPOINT ["/app/scanner"]
CMD ["-db", "/app/data/scanner.db", "-mqtt", "tcp://mosquitto:1883"]
