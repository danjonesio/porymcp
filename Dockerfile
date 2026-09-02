# syntax=docker/dockerfile:1

FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM golang:1.26-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# The dashboard is compiled into the binary (web/fs.go: //go:embed all:out),
# so the Go build needs the export from the web stage before it can compile.
COPY web/fs.go ./web/fs.go
COPY --from=web /web/out ./web/out
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /porymcp ./cmd/server
# Empty /data for the runtime stage below (distroless has no shell or mkdir).
RUN mkdir -p /data

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /porymcp /porymcp
COPY openapi.yaml /openapi.yaml
# /data holds the SQLite database (DATA_DIR, DATABASE_URL). Ship it owned by
# nonroot (uid 65532) so a freshly created volume mounted here is writable by
# the server; a root-owned mountpoint makes SQLite fail with "unable to open
# database file (14)" and the container exits.
COPY --from=build --chown=65532:65532 /data /data
ENV LISTEN_ADDR=:8080 \
    DATA_DIR=/data \
    DATABASE_URL=sqlite:///data/porymcp.db
EXPOSE 8080
USER nonroot
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD ["/porymcp", "healthcheck"]
ENTRYPOINT ["/porymcp"]
