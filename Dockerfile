# Build stage
FROM golang:1.26.6-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The api build auto-applies cmd/api/default.pgo (Go >=1.21) when present.
# Regenerate it from a representative workload after significant code changes —
# a stale profile is worse than none (inline decisions on dead hot spots).
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate

# Runtime stage
FROM alpine:3.24
# ca-certificates for outbound HTTPS (GitHub / Feishu / SMTP); tzdata keeps the
# process timezone sane.
RUN apk add --no-cache ca-certificates tzdata
# GOMEMLIMIT tells the Go runtime the container's memory ceiling (the 1c1g
# deployment caps at 1 GiB), so GC stays bounded instead of either over-collecting
# to burn the single core or under-collecting into an OOM.
ENV GOMEMLIMIT=900MiB
COPY --from=build /out/api /usr/local/bin/api
COPY --from=build /out/migrate /usr/local/bin/migrate
# Drop root. Both binaries are static, read their configuration from the
# environment, and write nothing to the filesystem, so there is nothing for a
# privileged user to do here. 8080 is above 1024, so binding it needs no
# capability.
RUN adduser -D -H -u 10001 sastlink
USER sastlink
EXPOSE 8080
# No ENTRYPOINT: the api service starts /usr/local/bin/api (default CMD) and the
# migrate service overrides command to run /usr/local/bin/migrate. A fixed
# ENTRYPOINT of "api" would turn "migrate up" into "api migrate up".
CMD ["/usr/local/bin/api"]
