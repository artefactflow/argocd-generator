# Build a static argocd-gen binary and ship it on a minimal, non-root runtime.
#
# The runtime image carries CA certificates and a non-root user: the plugin makes
# outbound HTTPS calls to the ArtefactFlow API, so a bare scratch image
# would fail TLS verification. distroless static-nonroot provides both and runs
# as an unprivileged user, matching the securityContext in deploy/plugin.yaml.
FROM golang:1.27 AS build
WORKDIR /src

# Module metadata first for layer caching. The module currently has no external
# dependencies, so this is effectively a no-op, but it keeps the cache warm if
# dependencies are added later.
COPY go.mod ./
RUN go mod download

COPY . .
ARG VERSION=dev
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/argocd-gen ./cmd/argocd-gen

FROM gcr.io/distroless/static-debian13:nonroot AS runtime
COPY --from=build /out/argocd-gen /usr/local/bin/argocd-gen

EXPOSE 4355/tcp
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/argocd-gen"]

# Default to the plugin server; override for CLI use (e.g. `generate ...`).
CMD ["serve", "--addr", ":4355"]
