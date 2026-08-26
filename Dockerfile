# Build stage
FROM golang:1.26.6-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The api build auto-applies cmd/api/default.pgo (Go >=1.21); regenerate it after
# significant code changes — a stale profile is worse than none (inline decisions
# on dead hot spots).
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate

# Runtime stage
FROM alpine:3.24
# ca-certificates for outbound HTTPS (GitHub / Feishu / SMTP); tzdata keeps the
# process timezone sane.
RUN apk add --no-cache ca-certificates tzdata
# GOMEMLIMIT tells the Go runtime the container's memory ceiling, keeping GC
# bounded.
ENV GOMEMLIMIT=900MiB
COPY --from=build /out/api /usr/local/bin/api
COPY --from=build /out/migrate /usr/local/bin/migrate
# Drop root: the binaries are static, read config from the environment, and write
# nothing, so no privileged user is needed. 8080 is above 1024, so binding it
# needs no capability.
RUN adduser -D -H -u 10001 sastlink
USER sastlink
EXPOSE 8080
# No ENTRYPOINT: api starts via the default CMD and migrate overrides the command.
# A fixed ENTRYPOINT of "api" would turn "migrate up" into "api migrate up".
CMD ["/usr/local/bin/api"]
