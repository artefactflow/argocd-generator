# How it works

A worked example, end to end: from one line of configuration to running Applications.

Everything below is real output. The parameter objects come from `argocd-gen generate --sbom-file example.sbomversion.json`, which you can run yourself without an ArtefactFlow account or a cluster.

## The one-line version

You tell Argo CD *which environment*. ArtefactFlow answers *what is in it*. The generator turns that answer into one `Application` per component.

```yaml
applicationSets:
  - name: production
    environment: production
```

That entry says: **whatever ArtefactFlow reports as live in the `production` environment, keep it deployed.** Add a component to production in ArtefactFlow and an Application appears; release a new version and the running image changes; remove it and the Application is pruned. Nobody edits a manifest in between.

## The chain

```
values.yaml            an ApplicationSet named "production", environment: production
   │
   ▼
ApplicationSet         plugin generator → calls this plugin every 120s
   │
   ▼
argocd-generator       asks ArtefactFlow three questions (below)
   │
   ▼
one parameter object   per component live in the environment
   │
   ▼
Argo CD                renders the ApplicationSet template once per object
   │
   ▼
Applications           one per component, synced as usual
```

## The three questions

On each reconcile the ApplicationSet controller POSTs to the plugin's `/api/v1/getparams.execute` with `{"environment": "production"}`. The plugin then asks ArtefactFlow:

1. **Which environment is this?** `GET /v1/environments?limit=100`. The deployments endpoint is keyed by id, not slug, so a human-friendly `production` is resolved to `0199149d-ec38-76c3-87d5-d2988b09b3c8` first. An id (a UUID) in `environment:` is used as-is and skips this call.

2. **What is live in it?** `GET /v1/environments/0199149d-ec38-76c3-87d5-d2988b09b3c8/deployments/active` returns the active deployment records, one per SBOM. ArtefactFlow keeps at most one active deployment per SBOM per environment; deploying a newer version supersedes the previous one.

   ```json
   { "sbom_id": "0199e573-fd0b-7cea-a378-b4f465211329", "sbom_name": "acme-platform-bom",
     "version_value": "2.4.0", "environment_slug": "production", "status": "active" }
   ```

3. **What is inside each of those?** `GET /v1/sboms/acme-platform-bom/versions/2.4.0` returns the CycloneDX document. Its `components` array is the environment's inventory, which is not the same as the set of things to deploy.

Not every component becomes an Application. Libraries are filtered out by type; components carrying no deployment configuration are inventory rather than deployments; and a component claimed by another (a container image deployed by a Helm chart) folds into the component that claims it. All three are reported by name, because with `prune: true` a component missing from the list is an Application Argo CD deletes. See [deployment-units.md](deployment-units.md).

A component that appears in several of the environment's SBOMs (a service belonging to two product bills) is emitted **once**, not once per SBOM. On a real environment that mattered: 18 component entries across the five SBOMs deployed to `production` resolve to 11 distinct identities. Repeats that disagree with each other are a conflict rather than a duplicate and fail loudly; see [configuration.md](configuration.md#shared-components).

## What a component looks like going in

An SBOM says *what* is live. It does not say *how* to deploy it. That travels as `argocd_*` **properties**, set on the artefact (defaults for every version) or on a specific version (per-release overrides), and resolved onto the component by ArtefactFlow with version-wins precedence.

Here is the `checkout-service-chart` component of the example SBOM as the API returns it, trimmed to the fields that matter:

```json
{
  "artefact_id": "0199830f-2660-740b-b394-21365f5a9e04",
  "bom-ref": "667b333c-d106-4fb6-8a16-0bc2413dc30d",
  "type": "application",
  "name": "checkout-service-chart",
  "group": "com.acme.payments",
  "version": "1.5.0",
  "purl": "pkg:helm/acme/checkout-service-chart",
  "source": "https://git.acme.example.com/gitops/charts/checkout-service",
  "properties": [
    { "name": "argocd_repo_url",        "value": "registry.acme.example.com/charts" },
    { "name": "argocd_chart",           "value": "checkout-service" },
    { "name": "argocd_target_revision", "value": "1.5.0" },
    { "name": "argocd_value_files",     "value": "apps/checkout-service/values.yaml" },
    { "name": "argocd_namespace",       "value": "payments" },
    { "name": "deploys-image",          "value": "pkg:docker/acme/checkout-service" },
    { "name": "artefact-kind",          "value": "helm-chart" }
  ]
}
```

The last two are not deployment configuration. `deploys-image` says *what this chart deploys*: the component `checkout-service`, which is in the same SBOM because an inventory has to include the image. That claim is what makes the chart and the image render as one Application instead of two fighting over the same workload. See [deployment-units.md](deployment-units.md).

## What comes out

One flat parameter object, every key always present:

```json
{
  "name": "checkout-service-chart-b98713cb",
  "rawName": "checkout-service-chart",
  "group": "com.acme.payments",
  "artefact_id": "0199830f-2660-740b-b394-21365f5a9e04",
  "purl": "pkg:helm/acme/checkout-service-chart",
  "purl_type": "helm",
  "source": "https://git.acme.example.com/gitops/charts/checkout-service",
  "image_repository": "acme/checkout-service",
  "image_tag": "1.5.0",
  "argocd_repo_url": "registry.acme.example.com/charts",
  "argocd_target_revision": "1.5.0",
  "argocd_path": "",
  "argocd_chart": "checkout-service",
  "argocd_value_files": ["apps/checkout-service/values.yaml"],
  "argocd_helm_parameters": [],
  "argocd_namespace": "payments",
  "argocd_project": "default"
}
```

Two things are derived rather than declared. `image_repository` and `image_tag` describe an image the chart's own `pkg:helm/...` purl says nothing about. They come from the claimed component, so the running image tracks the released version without anyone setting a property. (For a container component they come from its own purl and version instead.) And `name` is the component name sanitised to an RFC 1123 label with an eight-character hash of its stable identity appended, so two components that sanitise to the same string still get distinct Applications, and the name does not drift between reconciles.

## The Application Argo CD renders

Feeding that object through the shipped template ([`deploy/applicationset.yaml`](../deploy/applicationset.yaml), which is also the chart's default) produces:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: sbom-checkout-service-chart-b98713cb
  annotations:
    artefactflow.purl: pkg:helm/acme/checkout-service-chart
    artefactflow.component: checkout-service-chart
    artefactflow.artefact-id: 0199830f-2660-740b-b394-21365f5a9e04
spec:
  project: default
  destination:
    server: https://kubernetes.default.svc
    namespace: payments
  source:
    repoURL: registry.acme.example.com/charts
    targetRevision: 1.5.0
    chart: checkout-service
    helm:
      valueFiles:
        - apps/checkout-service/values.yaml
      parameters:
        - name: image.repository
          value: acme/checkout-service
        - name: image.tag
          value: "1.5.0"
  syncPolicy:
    automated: { prune: true, selfHeal: true }
    syncOptions: ["CreateNamespace=true"]
```

One Application deploys the chart, and the chart deploys the image: the two `image.*` parameters come from the component the chart claimed, not from anything an operator wrote.

The annotations are the audit trail: given a running Application you can see which ArtefactFlow artefact and which exact package it came from.

## Eight components, four Applications

The example SBOM is the demo's `acme-k8s-infra-bom`: the Helm charts and the container images they deploy. Eight components, four services, and four Applications, because a chart and the image it deploys are one workload.

| Component | Properties set | What it produces |
| --- | --- | --- |
| `checkout-service-chart` | repo (a chart registry), `argocd_chart`, `argocd_target_revision`, value files, namespace, `deploys-image` | A Helm **chart** at version `1.5.0`, image derived from the claimed component |
| `billing-worker-chart` | the same, no extra chart values | Same shape, one values file |
| `notification-gateway-chart` | the same plus `argocd_helm_parameters` | Two extra chart values on top of the derived image parameters |
| `analytics-pipeline-chart` | the same plus three `argocd_helm_parameters` | Replica count and resource limits alongside the image |
| the four `*-service` / `*-worker` images | deployment properties of their own | **Nothing**: each is claimed by its chart and folds into it |

Running it prints the parameters on stdout and the reasons on stderr:

```
$ argocd-gen generate --sbom-file example.sbomversion.json
4 component(s) not rendered as Applications:
  [skip] analytics-pipeline (pkg:docker/acme/analytics-pipeline): folded-into analytics-pipeline-chart
  [skip] billing-worker (pkg:docker/acme/billing-worker): folded-into billing-worker-chart
  [skip] checkout-service (pkg:docker/acme/checkout-service): folded-into checkout-service-chart
  [skip] notification-gateway (pkg:docker/acme/notification-gateway): folded-into notification-gateway-chart
```

The images still carry `argocd_path` and `argocd_namespace` of their own, and they would deploy perfectly well on their own if nothing claimed them. What decides it is the claim, not the absence of configuration.

`notification-gateway-chart` sets `argocd_helm_parameters = ingress.enabled=true,ingress.className=contour`, which lands after the image parameters:

```yaml
      parameters:
        - name: image.repository
          value: "acme/notification-gateway"
        - name: image.tag
          value: "2.2.0-rc1"
        - name: "ingress.enabled"
          value: "true"
        - name: "ingress.className"
          value: "contour"
```

The two image parameters are emitted first and need no configuration: they are what makes a new release actually roll out. Because Helm's later parameters win, naming them again in `argocd_helm_parameters` overrides them; that is the escape hatch, not the normal path. See [configuration.md](configuration.md#values-files-and-helm-parameters).

`argocd_chart` and `argocd_path` are the fork in the road: set `argocd_chart` and the source is a chart pulled from a Helm repository, leave it empty and the source is a path in a Git repository. That branch lives in the ApplicationSet's `templatePatch`, because a structured template cannot express a conditional.

### What the other SBOMs in the environment show

Rendering the whole `production` environment rather than this one file brings in four more SBOMs, and two more kinds of exclusion:

```
  [skip] acme-mobile-sdk (pkg:maven/com.acme/acme-mobile-sdk): component-type library
  [skip] acme-mobile-app (pkg:generic/acme-mobile-app): no-deployment-config
  [skip] admin-portal (pkg:npm/%40acme/admin-portal): no-deployment-config
```

`admin-portal` is an npm package and `acme-mobile-app` a mobile application. Both are legitimately in the environment's inventory and neither is an Argo CD Application under any definition, so neither carries an `argocd_*` property and both are skipped. `acme-mobile-sdk` is a `library`, which the type filter excludes before the question even arises.

A component that carries *some* `argocd_*` properties but not enough is the opposite case (a misconfiguration, not inventory) and it fails rather than being skipped. Nothing in the demo data is in that state, but it is the easiest mistake to make: give `admin-portal` an `argocd_path` and nothing else, and it stops being inventory without becoming deployable, because its group is reverse-DNS and there is no namespace to fall back on:

```
component "admin-portal": no argocd_namespace property, and its group "com.acme.web"
is not a valid Kubernetes namespace; set argocd_namespace on the artefact or version
(or configure a default namespace)
```

The distinction is worth being clear about: nothing at all means "not a deployment", and is skipped. Something-but-not-enough means "a deployment somebody has not finished configuring", and fails, because failing is what stops a half-configured component from being pruned.

That is the deliberate choice, because the plausible guesses are worse. The sync policy sets `CreateNamespace=true`, so a rewritten `com-acme-web` would not be rejected. Argo CD would create it, and the deployment would report Synced while running somewhere nobody chose. Failing costs you one property; guessing costs you a silent misdeployment. If you genuinely want a catch-all, opt into one with `--default-namespace` (chart: `plugin.defaultNamespace`).

Components whose `group` is already a flat name (`payments`) need no property at all, because the fallback applies whenever it is actually safe. See [configuration.md](configuration.md#namespaces).

## What changes when

| You do this in ArtefactFlow | The next reconcile does this |
| --- | --- |
| Deploy version `1.6.0` of an SBOM to production | `image_tag` becomes `1.6.0`; Argo syncs the new image |
| Add a component to the SBOM and release it | A new Application appears |
| Remove a component and release | Its Application is pruned |
| Change an `argocd_*` property on the artefact | Applies from the next SBOM version; a released version is immutable |
| Deploy the same SBOM to `staging` too | Nothing, unless you declare a second `applicationSets` entry for it |

That last row is the reason `applicationSets` is a list. One entry per environment you want Argo CD to manage; they are independent, and each can carry its own project, destination, and sync policy.

Because a released SBOM version is immutable, its resolved properties are fixed at release time. Anything that must change *without* cutting a new version belongs in the ApplicationSet template (the operator layer) rather than in a property.

## Two environments

```yaml
applicationSets:
  - name: production
    environment: production
    project: platform-prod

  - name: staging
    environment: staging
    project: platform-staging
    syncPolicy:
      automated:
        prune: true
        selfHeal: false        # let engineers experiment in staging
```

Each entry inherits the chart's defaults for anything it does not set, so a second environment is usually three lines.

## Why it never returns a partial set

If any member SBOM cannot be resolved or fetched (a network blip, a revoked token, a group the service account cannot read) the plugin fails the whole request rather than returning the components it did manage to load.

This is deliberate, and it is the single most important correctness property here. The ApplicationSet controller treats the parameter list as the complete desired state: a component missing from the list is a component that should no longer exist, and with `prune: true` it gets deleted. A partial response would therefore delete healthy production Applications because of a transient API error. Failing the request instead makes the reconcile error, and Argo CD keeps its last known-good set.

For the same reason an environment that genuinely has *nothing* deployed is refused by default; set `plugin.allowEmpty: true` only if an empty environment should really mean "delete everything".

## Trying it without a cluster

```sh
# No API, no Argo CD: render the bundled example
argocd-gen generate --sbom-file example.sbomversion.json

# Against a real environment
export ARTEFACTFLOW_CLIENT_ID=…
export ARTEFACTFLOW_CLIENT_SECRET=…
argocd-gen generate --environment production --api-url https://api.artefactflow.app
```

The CLI prints exactly what the plugin would return, which makes it the fastest way to check a property change or to diff two environments in CI.

The parameters go to stdout and the exclusion report to stderr, so a pipeline can consume the JSON while a human still sees what was left out. `--quiet` drops the report. Run this before changing deployment properties: the components it lists as excluded are exactly the Applications Argo CD would prune.

The report also carries `[note]` advisories, which exclude nothing. They cover the opposite failure: a chart that *should* claim an image but does not removes nothing, so it would otherwise be reported nowhere while quietly deploying twice. See [deployment-units.md](deployment-units.md).
