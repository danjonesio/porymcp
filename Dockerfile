# syntax=docker/dockerfile:1

# Both build stages run on the builder's own architecture: the export is the
# same for every target, and the Go compiler cross-compiles by argument. Only
# the runtime stage below resolves per target platform. Pinned by index digest
# for the same reason as the Go base image.
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
# The dashboard is compiled into the binary (web/fs.go: //go:embed all:out),
# so the Go build needs the export from the web stage before it can compile.
COPY web/fs.go ./web/fs.go
COPY --from=web /web/out ./web/out
# BuildKit sets these per target platform. A plain docker build gets the host's.
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /porymcp ./cmd/server
# Empty /data for the runtime stage below (distroless has no shell or mkdir).
RUN mkdir -p /data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
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
