.PHONY: dev test test-race vet vuln web web-dev web-test web-lint web-typecheck web-audit web-e2e build tidy smoke image-check

dev:
	go run ./cmd/server

# test is the local loop: the dashboard unit tests (web-test), then the Go
# suites. The unit tests import only Node's built-ins and each other, which the
# web job proves on every run by running them before npm ci, so they need Node
# (web/.nvmrc) and no install. CI runs the halves in separate jobs: test-race
# in the go job, web-test in the web job.
test: web-test
	go test ./cmd/... ./internal/... ./scripts/... ./web

# test-race is the Go suites under the race detector, Go only, as the go job
# in .github/workflows/ci.yml runs them.
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

# web-test runs the dashboard unit tests with node --test, which strips the
# types itself from Node 22.18. The first line names the release web/.nvmrc
# asks for when the installed Node cannot, instead of a stack trace.
web-test:
	@node -e 'process.exit(process.features.typescript ? 0 : 1)' 2>/dev/null || { echo "web-test needs a Node that strips types: use the release in web/.nvmrc (nvm use)" >&2; exit 1; }
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

# image-check runs scripts/image-check.sh against an image already on this
# host. The recipe is silent and names no variable: the script reads
# IMAGE_CHECK_REF, IMAGE_CHECK_ARCH, IMAGE_CHECK_STUB and IMAGE_CHECK_E2E
# from the environment it inherits and mints its own keys.
image-check:
	@bash scripts/image-check.sh

# web-e2e runs the browser suite (web/e2e) against a binary scripts/web-e2e.sh
# starts on free loopback ports. It has no prerequisite because npm ci must
# come before make build on a fresh checkout; the recipe names no key.
web-e2e:
	@[ -d web/node_modules ] || (cd web && npm ci --no-audit --no-fund)
	@$(MAKE) build
	@bash scripts/web-e2e.sh
