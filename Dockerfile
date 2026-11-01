# Both build stages run on the builder's own architecture: the export is the
# same for every target, and the Go compiler cross-compiles by argument. Only
# the runtime stage below resolves per target platform. Pinned by index digest
# for the same reason as the Go base image.
# No syntax directive is declared, because no instruction here needs an
# external frontend. Add one back, pinned by digest, when this file first uses
# a heredoc, COPY --link or RUN --mount.
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
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
