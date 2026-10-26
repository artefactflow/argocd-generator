# argocd-generator

## What is ArtefactFlow?

[ArtefactFlow](https://www.artefactflow.com) is a hosted platform for managing software artefacts and their Software Bills of Materials. It gives your team one source of truth for every application, library and image you ship: each artefact and its versions, the licenses and vulnerabilities they carry, the immutable CycloneDX SBOMs that describe them, and a record of which SBOM version is running in which environment. So when someone asks what is inside a release, whether it is vulnerable, or what exactly is in production right now, there is one answer rather than four.

Everything is available over a REST API, which is what makes integrations like this one possible. [Create an account](https://www.artefactflow.com) to get started, or read the [documentation](https://docs.artefactflow.com) for the full picture.

## What this tool does

Turn what ArtefactFlow reports as deployed to an environment into Argo CD `Application` manifests. You declare an environment; ArtefactFlow is the source of truth for the set of SBOMs and versions live in it; this tool renders the GitOps manifests to deploy that set.

It runs two ways over one core:

- **CLI**: `generate` prints Argo CD ApplicationSet parameters to stdout, for local development, CI diffing, and testing.
- **ApplicationSet plugin generator**: `serve` runs a small HTTP service that Argo CD's ApplicationSet controller calls each reconcile, returning one parameter object per component so it renders one `Application` per component.

## How it works

For an environment, the tool asks ArtefactFlow which SBOM versions are active, fetches each version document, and turns every component into one parameter object. An SBOM says *what* is live (name, version, image); the deployment configuration (repository, chart or path, values files) travels as `argocd_*` properties on the artefact/version and is read from the same document.

So one line of configuration:

```yaml
applicationSets:
  - name: production
    environment: production
```

becomes one Argo CD `Application` per component that ArtefactFlow reports as live in `production`, refreshed every reconcile. Release a new version there and the image tag follows; remove a component and its Application is pruned.

- **[docs/how-it-works.md](docs/how-it-works.md)**: the whole chain walked end to end with real output. Start here.
- **[docs/configuration.md](docs/configuration.md)**: the `argocd_*` property reference.
- **[docs/deployment-units.md](docs/deployment-units.md)**: which components become Applications, and why not all of them do.

The environment's deployment set is treated as the source of truth for what should be live. If any member SBOM cannot be resolved or fetched, the whole operation fails rather than returning a partial set. A missing Application in a generated set is a failed deployment, so it is surfaced, never silently dropped.

Not every component becomes an Application, though. An SBOM is an inventory (it includes the container images where vulnerabilities live) while Argo CD wants a deployment topology. A Helm chart and the image it deploys are one workload described twice, so the chart claims the image with a `deploys-image` property and the two render as a single Application. Components carrying no deployment configuration at all are inventory and are skipped. Every exclusion is printed with its reason, because with `prune: true` a component missing from the list is an Application Argo CD deletes. See [docs/deployment-units.md](docs/deployment-units.md).

## CLI

```sh
# Offline: render a local SBOM version document
argocd-gen generate --sbom-file example.sbomversion.json

# Every SBOM live in an environment (slug or id)
argocd-gen generate --environment production --api-url https://api.artefactflow.app

# A single SBOM version
argocd-gen generate --sbom acme-platform-bom --version 2.4.0 --api-url https://api.artefactflow.app
```

Environment and single-SBOM modes authenticate as an ArtefactFlow service account:

```sh
export ARTEFACTFLOW_CLIENT_ID=01990d1e-eadc-7075-9866-e07979322b2a    # the account's own id, a UUID
export ARTEFACTFLOW_CLIENT_SECRET=afsa_…                  # from a secret store, never a flag
export ARTEFACTFLOW_API_URL=https://api.artefactflow.app
argocd-gen generate --environment production
```

The client id may also be passed as `--client-id`; the secret is read from the environment only, because a flag value shows up in `ps` output and in shell history. Both are exchanged for a short-lived access token on first use. The service account needs the `sbom:read` and `environment:read` scopes, and team membership granting read access to the relevant groups.

An already-minted bearer token is deliberately not accepted. It would make it easy to run the generator as a human user, carrying that person's full scope set and breaking when they leave, and the long-running plugin would be holding a credential that expires long before it does.

## Plugin generator

```sh
argocd-gen serve --addr :4355
```

The server implements `POST /api/v1/getparams.execute`. Two independent credentials are in play:

- **Plugin token** (`ARGOCD_PLUGIN_TOKEN`): the ApplicationSet controller presents this to the plugin; requests without it get `403`.
- **Service account** (`ARTEFACTFLOW_CLIENT_ID` / `ARTEFACTFLOW_CLIENT_SECRET`): the plugin presents these to ArtefactFlow. The controller never sees them.

The plugin caches its access token and re-mints it shortly before expiry, so one reconcile costs one token rather than one per component, and a process that runs for weeks keeps working without an operator rotating anything. If the API rejects a token it believed was still valid (early expiry, or a revocation) the plugin re-authenticates once and retries rather than failing the reconcile.

The request's `input.parameters.environment` (required) selects the environment; `input.parameters.sbomName` (optional) restricts the output to a single SBOM.

### Pruning safety

The plugin never returns a `200` with an empty or partial parameter list, because an empty result tells the controller every generated Application is gone and it prunes them all. A failed resolve returns a non-2xx status so the reconcile errors and Argo keeps its last known-good set. An environment that genuinely has nothing deployed is also refused by default; pass `serve --allow-empty` if you want an empty environment to prune every Application.

## Deploying to Argo CD

### Helm chart (recommended)

```sh
helm install argocd-generator oci://ghcr.io/artefactflow/charts/argocd-generator \
  --namespace argocd --values my-values.yaml
```

The chart in [charts/argocd-generator/](charts/argocd-generator/) installs the plugin, its credentials, a `NetworkPolicy`, and one `ApplicationSet` per environment you declare in `values.yaml`:

```yaml
artefactflow:
  clientId: 01990d1e-eadc-7075-9866-e07979322b2a
  existingSecret: artefactflow-credentials   # key: client-secret
plugin:
  existingSecret: argocd-generator-plugin-token
applicationSets:
  - name: production
    environment: production
```

See the [chart README](charts/argocd-generator/README.md) for every value. One prerequisite the chart deliberately leaves alone, because it belongs to your Argo CD install: plugin generators are disabled by default, so enable `applicationsetcontroller.enable.plugin` in `argocd-cmd-params-cm` and restart the controller.

### Raw manifests

If you would rather patch YAML by hand, the same setup is in [deploy/](deploy/):

1. [`enable-plugin-generator.yaml`](deploy/enable-plugin-generator.yaml): enable plugin generators, then restart the controller.
2. [`plugin.yaml`](deploy/plugin.yaml): the plugin `ConfigMap`, both credentials, and the `Deployment`/`Service`.
3. [`networkpolicy.yaml`](deploy/networkpolicy.yaml): restrict ingress to the ApplicationSet controller.
4. [`applicationset.yaml`](deploy/applicationset.yaml): the `ApplicationSet` that consumes the plugin.

## Security

To report a security issue, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Build and test

```sh
go build ./...
go test ./...
helm lint charts/argocd-generator --set artefactflow.clientId=0199cffa-e497-7ef0-b9c5-7babd3c0e9fc --set artefactflow.clientSecret=s --set plugin.token=p
```
