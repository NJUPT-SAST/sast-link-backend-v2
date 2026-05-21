.PHONY: build run test migrate-up migrate-down docker-up docker-down lint fmt tidy

build:
	go build -o bin/api ./cmd/api

run:
	go run ./cmd/api

test:
	go test -v -race -cover ./...

tidy:
	go mod tidy

migrate-up:
	migrate -path ./migrations -database "$(DATABASE_URL)" up

migrate-down:
	migrate -path ./migrations -database "$(DATABASE_URL)" down 1

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down -v

lint:
	golangci-lint run

fmt:
	go fmt ./...
