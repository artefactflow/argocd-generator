# Which components become Applications

Not every component of an environment's SBOMs becomes an Argo CD `Application`. This page explains what is excluded, why, and how to see it.

## Inventory is not topology

An SBOM is an **inventory**: the complete set of what is inside a release. That completeness is the point: vulnerabilities live in the container image, not in the Helm chart, so an inventory of production that omits images cannot answer "what is vulnerable in production".

Argo CD needs a **deployment topology**: the set of root units to reconcile, each with its own source and destination.

These are two different graphs over the same components. The generator's job is to derive the second from the first, and the interesting cases are where one component does not equal one deployment unit.

## Three rules

### 1. A chart and the image it deploys are one workload

A Kubernetes SBOM typically contains both:

```
CHART checkout-service-chart   purl=pkg:helm/acme/checkout-service-chart
image checkout-service         purl=pkg:docker/acme/checkout-service
```

Both belong in the inventory. But they are one deployment described from two angles: the *how* and the *what*. Rendering both produces two Applications: the chart installs the service, and a second Application installs it again from plain manifests. In a cluster the two fight over the same workload.

The chart artefact says what it deploys:

```
deploys-image = pkg:docker/acme/checkout-service
```

The claimer becomes the deployment root; the claimed component folds into it.

This also fixes something a chart cannot express alone. Its purl is `pkg:helm/...`, so it carries no image of its own, and `image_repository` comes out empty even though deploying the chart is precisely how the image reaches the cluster. The claim supplies it: `image_repository` and `image_tag` are derived from the claimed component, so no chart has to restate them by hand.

**Why the property is not `argocd_deploys`.** The `argocd_*` properties describe *how* to deploy something. This one records *what a thing is*: the chart deploys that image whether or not Argo CD exists. Keeping it unprefixed means other tooling can read the same relationship.

**Why not the CycloneDX `dependencies` graph.** `dependsOn` means depends-on, not deploys-and-subsumes. Folding "anything claimed by another component" is safe only while that graph is empty. If it is populated properly, ordinary dependency edges (subcharts, base images, libraries) would start demoting components that genuinely are roots. Using the graph would need a qualified edge, not bare `dependsOn`.

Two cases that are reported rather than fatal:

- **Several charts claiming one image**: a shared sidecar, or a job chart beside a service chart. The image is not a deployment root either way, and both claimers still render. Every claimer is named in the report.
- **A claim naming something absent from the environment**: its SBOM may simply not be deployed here. The repository is still recoverable from the claim's own purl; only the tag is lost.

Failing the whole environment for either would take down every Application in it over a data quirk.

#### One chart that deploys many workloads

The claim runs chart → image and folds the image into the chart, so it describes exactly one workload. A **shared** chart (one chart that deploys five services, which is the common house-chart arrangement) cannot be expressed that way, and the shape of the failure is worth understanding rather than working around:

- `deploys-image` holds a single package URL (a value that is not one is a hard error), so there is no "these five images" form of the claim.
- Even if there were, the chart is **one component**, so it is one Application name, one destination namespace and one set of Helm parameters. Five releases of a chart need five deployment roots, and a claim can only ever produce one.

So invert it. The **image is the deployment root** and the chart is just where its manifests come from, named on the image's own properties:

```
argocd_repo_url        = https://charts.acme.example.com
argocd_chart           = service-chart
argocd_target_revision = 3.3.0
argocd_namespace       = storefront
argocd_helm_parameters = fullnameOverride=search-api
```

Nothing here is special-cased for charts: `argocd_chart` is read off whatever component carries it, and a `pkg:docker/...` component supplies `image_repository` and `image_tag` from its own purl, so a service names the chart that deploys it and still carries its own image. Each service renders as its own Application against the shared chart.

The shared chart artefact then carries **no** `argocd_*` property and **no** `deploys-image`, which makes it inventory (rule 2): present in the bill, reported as a `[skip] no-deployment-config`, never a deployment root. It is also filtered before claims are collected, so a `deploys-image` accidentally left on a chart with no deploy config cannot fold anything.

Two consequences:

- `fullnameOverride` (or whatever your chart calls it) matters here in a way it does not for a dedicated chart. Several releases of one chart in one namespace collide on resource names otherwise, and the Application name carries a hash suffix you would not want in a Service name.
- The chart **version** is a property of each service rather than of the chart component. Put it on the artefact as the default and override it on a version when a service pins a chart it has not yet moved off, and that pin is then frozen into the released, signed SBOM version. If every consumer always runs the same chart version, it belongs in the ApplicationSet template instead; see the layering rule in [configuration.md](configuration.md#two-layers-of-configuration).

Use `deploys-image` when a chart exists to deploy one image and would otherwise double-deploy it. Use the inversion when one chart serves many. They coexist in a single environment without interfering.

### 2. No `argocd_*` property at all means inventory

An environment legitimately contains things that are not Argo CD Applications under any definition: an npm package, a mobile app, an SDK. A component carrying no `argocd_*` property whatsoever is inventory and is skipped.

A component carrying *some* `argocd_*` properties but not enough to deploy is a different thing entirely: that is a misconfiguration, and it still fails loudly. The distinction is the point: failing is what stops a half-configured component from being pruned.

The test is on the raw property list, not on the rendered parameters. After defaulting almost everything looks configured, because `argocd_repo_url` falls back to the component's `source`. What distinguishes a deployment from inventory is that somebody wrote deployment configuration onto it.

`--deploy-unconfigured` renders everything regardless.

### 3. Only selected component types

`application` and `container` by default; a `library` is not a deployment. `--component-types` changes the list, and `--component-types all` disables the filter.

## Everything excluded is reported

This is the rule the rest of the tool is built around. Argo CD treats the returned list as the complete desired state, so with `prune: true` **a component missing from the list is an Application it deletes**. A filter that drops something quietly is indistinguishable from a forgotten property, until an Application disappears from production.

So every exclusion is named, with its reason. The CLI prints the report to stderr, leaving stdout as clean JSON:

```
$ argocd-gen generate --environment production
7 component(s) not rendered as Applications:
  [skip] acme-mobile-sdk (pkg:maven/com.acme/acme-mobile-sdk): component-type library
  [skip] analytics-pipeline (pkg:docker/acme/analytics-pipeline): folded-into analytics-pipeline-chart
  [skip] billing-worker (pkg:docker/acme/billing-worker): folded-into billing-worker-chart
  [skip] checkout-service (pkg:docker/acme/checkout-service): folded-into checkout-service-chart
  [skip] notification-gateway (pkg:docker/acme/notification-gateway): folded-into notification-gateway-chart
  [skip] acme-mobile-app (pkg:generic/acme-mobile-app): no-deployment-config
  [skip] admin-portal (pkg:npm/%40acme/admin-portal): no-deployment-config
```

`--quiet` suppresses it. `serve` logs the same information: in full whenever the set of exclusions changes, and as a summary while it holds steady, because the controller reconciles every couple of minutes and runs for weeks, so restating an unchanged report every time would bury it.

Run the CLI against an environment before changing deployment properties or upgrading. The report tells you which components would stop being Applications, which is the same thing as telling you what Argo CD would prune.

## Advisories: when nothing was excluded but something looks wrong

The report above explains what was *removed*. The opposite failure is quieter and worse: a chart that should claim an image but does not. Nothing is removed, so nothing is reported, and both components deploy: the double-deployment problem the claim exists to prevent.

Two advisories catch that. Neither excludes anything and neither fails the run; they appear as `[note]` lines in the same report.

**`unclaimed-pair`**: a `pkg:helm/...` component and a `pkg:docker/...` component whose names differ only by a `chart` prefix or suffix, where neither claims the other:

```
  [note] checkout-service-chart (pkg:helm/acme/checkout-service-chart): unclaimed-pair looks like it deploys checkout-service (pkg:docker/acme/checkout-service); set deploys-image on the chart or both will deploy
```

The match is deliberately narrow. A chart whose image is not in the same environment is completely normal, so an advisory on every unclaimed chart would fire constantly and train people to ignore the report.

**`claim-property-typo`**: a component carrying a property that normalises to the claim property but is not spelled correctly, such as `deploys_image` or `deploysImage`:

```
  [note] billing-worker-chart (pkg:helm/acme/billing-worker-chart): claim-property-typo property "deploys_image" looks like "deploys-image" but is not read
```

A misspelled property is simply an unread property, which is otherwise indistinguishable from not having set one.

## Unresolved components are an error

When ArtefactFlow cannot resolve a component's artefact, the API returns the bare reference (`{"artefact_id": "...", "version": "1.5.0"}`) with no name, type or purl, and reports nothing to the consumer.

Such a component cannot be rendered. Having no type, it would also be discarded by the type filter, so an environment whose components all came back unresolved would produce an *empty* parameter set: the single most destructive response available, since it tells Argo CD every Application is gone.

The generator therefore fails, naming the artefact. If an environment suddenly refuses to render with this error, ArtefactFlow could not resolve that artefact at the time of the request. The cause is on the ArtefactFlow side rather than in your configuration, and a reconcile retries it; Argo CD keeps the last good set of Applications in the meantime.

## Reasons in the report

Exclusions, where the component is not in the returned set:

| Reason | Meaning |
|---|---|
| `folded-into` | Another component claimed this one; the detail names the claimer(s). |
| `no-deployment-config` | No `argocd_*` property at all: inventory, not a deployment. |
| `component-type` | The CycloneDX type is not in `--component-types`. |

Advisories, where the component still renders:

| Reason | Meaning |
|---|---|
| `claim-target-absent` | A claim names something not in this environment; no tag could be derived. |
| `unclaimed-pair` | A chart and an image look like a pair, but neither claims the other. |
| `claim-property-typo` | A property is spelled almost like the claim property and is being ignored. |

## Turning it off

| Flag | Effect |
|---|---|
| `--no-fold` | Render claimed components as their own Applications. |
| `--deploy-unconfigured` | Render components with no `argocd_*` property. |
| `--component-types all` | Disable the type filter. |
| `--claim-property` | Read the claim from a property other than `deploys-image`. |

All four are accepted by both `generate` and `serve`, and are exposed as Helm values on the chart.
