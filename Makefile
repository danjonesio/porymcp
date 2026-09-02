.PHONY: dev test test-race web web-dev web-test build tidy

dev:
	go run ./cmd/server

test:
	go test ./cmd/... ./internal/... ./web

test-race:
	go test -race ./cmd/... ./internal/... ./web

tidy:
	go mod tidy

web-dev:
	cd web && npm run dev

web-test:
	cd web && npm test

web:
	cd web && npm run build

build: web
	go build -o bin/porymcp ./cmd/server
