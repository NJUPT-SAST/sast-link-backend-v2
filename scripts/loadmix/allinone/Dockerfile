# SAST Link 1c1g bench container: PostgreSQL + Redis + the API in one box
# sharing `--cpus=1 --memory=1g`, so every measurement is on an honest single
# core with the API, the database, and the cache competing for it.
#
# The api/migrate binaries are prebuilt on the host for the Docker daemon's own
# architecture (see build.sh) and copied in — this image is a bench harness, not a
# deployment target. `run-bench.sh` starts a container from it after the image is
# built.
FROM postgres:16-alpine

RUN apk add --no-cache bash redis

WORKDIR /app
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY api /usr/local/bin/api
COPY migrate /usr/local/bin/migrate
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/api /usr/local/bin/migrate

EXPOSE 5432 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
