.PHONY: dev test test-race vet vuln web web-dev web-test web-lint web-typecheck web-audit build tidy smoke

dev:
	go run ./cmd/server

test:
	go test ./cmd/... ./internal/... ./scripts/... ./web

test-race:
	go test -race ./cmd/... ./internal/... ./scripts/... ./web

vet:
	go vet ./cmd/... ./internal/... ./scripts/... ./web
	@files="$$(git ls-files '*.go' 2>/dev/null)"; [ -n "$$files" ] || files="./cmd ./internal ./web"; unformatted="$$(gofmt -l $$files)"; if [ -n "$$unformatted" ]; then echo "gofmt -l: $$unformatted"; exit 1; fi

vuln:
	go tool govulncheck ./cmd/... ./internal/... ./scripts/... ./web

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

web-audit:
	cd web && npm audit --audit-level=high

web:
	cd web && npm run build

build: web
	go build -o bin/porymcp ./cmd/server

# smoke runs scripts/smoke.sh against SMOKE_BASE (default http://localhost:8080).
# The recipe is silent and names no variable: the script reads ADMIN_API_KEY,
# STUB_URL and the SMOKE_* inputs from the environment it inherits.
smoke:
	@bash scripts/smoke.sh
