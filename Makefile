.PHONY: dev test test-race vet vuln web web-dev web-test web-lint web-typecheck build tidy

dev:
	go run ./cmd/server

test:
	go test ./cmd/... ./internal/... ./web

test-race:
	go test -race ./cmd/... ./internal/... ./web

vet:
	go vet ./cmd/... ./internal/... ./web
	@unformatted="$$(gofmt -l $$(git ls-files '*.go'))"; if [ -n "$$unformatted" ]; then echo "gofmt -l: $$unformatted"; exit 1; fi

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./cmd/... ./internal/... ./web

tidy:
	go mod tidy

web-dev:
	cd web && npm run dev

web-test:
	cd web && npm test

web-lint:
	cd web && npm run lint

web-typecheck:
	cd web && npx tsc --noEmit

web:
	cd web && npm run build

build: web
	go build -o bin/porymcp ./cmd/server
