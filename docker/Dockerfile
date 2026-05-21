# Build stage
FROM golang:1.26.3-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates tzdata wget

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /app/bin/api \
    ./cmd/api

# Runtime stage
FROM alpine:3.21

WORKDIR /app

RUN apk --no-cache add ca-certificates wget

COPY --from=builder /app/bin/api /app/api
COPY --from=builder /app/migrations /app/migrations

RUN adduser -D -g '' appuser
USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/api"]
