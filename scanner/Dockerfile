FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS builder

ARG TARGETOS
ARG TARGETARCH
ARG BUILD_VERSION=dev

WORKDIR /app

# Copy source code first so 'go mod tidy' knows what to fetch
COPY . .
RUN go mod tidy

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath -buildvcs=false \
    -ldflags "-X main.scannerVersion=$BUILD_VERSION" \
    -o scanner .

# This target contains the complete external-scanner-free runtime.
FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1 AS runtime
RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY --from=builder /app/scanner .

# Ensure DB is persistent via volume mount to /app/data
ENV DB_PATH=/app/data/scanner.db
RUN mkdir -p /app/data

ENTRYPOINT ["/app/scanner"]
CMD ["-db", "/app/data/scanner.db", "-mqtt", "tcp://mosquitto:1883"]
