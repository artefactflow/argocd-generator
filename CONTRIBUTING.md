# Contributing

Thanks for taking the time. Bug reports, documentation fixes, and pull requests are all welcome. To report a security vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening an issue.

## Getting started

The generator is a small Go program with no third-party dependencies, shipped as a container image and a Helm chart. You need Go (the version in [go.mod](go.mod)), and Docker and Helm to build the image and work on the chart.

```sh
go build ./...
go test ./...
```

## Running it locally

The `generate` command prints the parameter objects the plugin would return to Argo CD, without talking to Argo CD at all, so it is the quickest way to see what a change does against real data:

```sh
export ARTEFACTFLOW_API_URL=https://api.artefactflow.app
export ARTEFACTFLOW_CLIENT_ID=...       # the service account's id, a UUID
export ARTEFACTFLOW_CLIENT_SECRET=...

go run ./cmd/argocd-gen generate --environment production
go run ./cmd/argocd-gen generate --sbom acme-platform-bom --version 2.4.0
```

The parameter objects go to stdout and the exclusion report to stderr, so `> out.json` captures a clean result for diffing. The service account only needs read access: the `sbom:read` and `environment:read` scopes, and team membership granting read access to the groups the environment's SBOMs belong to.

`go run ./cmd/argocd-gen serve` runs the plugin server the ApplicationSet controller calls; see [docs/how-it-works.md](docs/how-it-works.md) for the request it expects.

## Before opening a pull request

CI runs these, so running them first saves a round trip:

```sh
gofmt -l .        # must print nothing
go vet ./...
go test -race ./...
helm lint charts/argocd-generator --set artefactflow.clientId=0198e2c3-9a21-7b8e-90f5-6c1d4e2a83b0 --set artefactflow.clientSecret=s --set plugin.token=p
docker build .
```

## Conventions

- A component missing from the output is a component Argo CD deletes. Never drop one silently: either render it, or exclude it with a reason in the exclusion report, or fail the whole request so Argo CD keeps its last good set. There are tests asserting each of these; keep them passing.
- The rendered parameter objects are pinned by golden files under `internal/render/testdata`. After a deliberate change, regenerate it with `go test ./internal/render -update` and review the diff: it is the specification of what Argo CD receives.
- The client secret and the minted token must never reach a log line, an error message, or a response. There are tests asserting this; keep them passing.
- The secret is read from the environment only, never from a flag, because a flag value shows up in `ps` output and shell history.
- Prose in Markdown is written as one unwrapped line per paragraph: do not hard-wrap at a column.
- Do not edit `CHANGELOG.md`.

## Releasing

Releases are cut by maintainers by running the `Release` workflow by hand against a version tag such as `v1.2.3` (choose the tag, not a branch, under "Use workflow from"). It re-runs the tests, builds the multi-architecture image and scans it, and only then tags and attests the image, publishes the Helm chart to `oci://ghcr.io/artefactflow/charts` at the same version, and creates the GitHub release with the image SBOMs attached.
