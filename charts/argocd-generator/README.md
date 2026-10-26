# argocd-generator Helm chart

Installs the ArtefactFlow ApplicationSet plugin generator into an Argo CD cluster: the plugin `Deployment`/`Service`, the `ConfigMap` the plugin generator references, the two tokens, a `NetworkPolicy`, and one `ApplicationSet` per environment you declare.

The raw manifests in [`deploy/`](../../deploy/) do the same thing without a templating layer, so use those if you would rather patch YAML by hand.

## Install

```sh
helm install argocd-generator oci://ghcr.io/artefactflow/charts/argocd-generator \
  --namespace argocd \
  --values my-values.yaml
```

A minimal `my-values.yaml`:

```yaml
artefactflow:
  apiUrl: https://api.artefactflow.app
  clientId: 01990d1e-eadc-7075-9866-e07979322b2a  # the service account's id, a UUID
  existingSecret: artefactflow-credentials         # key: client-secret

plugin:
  existingSecret: argocd-generator-plugin-token

applicationSets:
  - name: production
    environment: production
```

## What an `applicationSets` entry does

```yaml
applicationSets:
  - name: production
    environment: production
```

That entry creates one `ApplicationSet` that asks this plugin, every 120 seconds, what ArtefactFlow reports as live in the `production` environment, and renders **one Argo CD `Application` per component** in the answer.

Concretely, per reconcile the plugin resolves the `production` slug to an environment id, lists its active deployments (one per SBOM), fetches each SBOM version document, and returns one parameter object per component. An SBOM of four components becomes four Applications:

```
sbom-checkout-service-e5e6295c        payments/checkout-service      1.5.0
sbom-billing-worker-7bccbbec          payments/billing-worker        0.9.1
sbom-notification-gateway-1a6a7a13    messaging/notification-gateway 2.2.0-rc1
sbom-admin-portal-c243ad5a            (npm, no image)                3.0.0
```

Release a new version to that environment in ArtefactFlow and the image tag changes on the next reconcile; remove a component and its Application is pruned. Nobody edits a manifest in between.

Where the *how* comes from (repo, chart or path, values files, Helm parameters, namespace) is the `argocd_*` property convention, documented in [configuration.md](../../docs/configuration.md). Values that differ per component belong there; values that are the same for every Application belong in this chart's `templatePatch`, which is the operator layer and is fully overridable from your own values file.

**[how-it-works.md](../../docs/how-it-works.md) walks the whole chain with real output**, from this YAML to the rendered `Application`. Start there if the above is the first time you have seen this tool.

Anything you leave out of an `applicationSets` entry falls back to the chart defaults, which reproduce [`deploy/applicationset.yaml`](../../deploy/applicationset.yaml). Add a second entry for a second environment; they are independent, and each can carry its own project, destination, and sync policy.

Plugin generators are disabled in Argo CD by default and this chart does not manage the ConfigMap that enables them: it belongs to your Argo CD install:

```sh
kubectl patch configmap argocd-cmd-params-cm -n argocd --type merge \
  -p '{"data":{"applicationsetcontroller.enable.plugin":"true"}}'
kubectl rollout restart deploy/argocd-applicationset-controller -n argocd
```

## Credentials

Two independent credentials are in play, and the ApplicationSet controller only ever sees the first:

| Value | Purpose |
| --- | --- |
| `plugin.token` | Shared secret the controller presents to this plugin. |
| `artefactflow.clientId` / `artefactflow.clientSecret` | The ArtefactFlow service account the plugin authenticates as. Needs `sbom:read` and `environment:read`, plus team membership granting read access to the relevant groups. |

Either secret can be supplied inline or, preferably, through `existingSecret`, because inline values land in the Helm release secret and in `helm get values`. The client id is an identifier rather than a credential, so it is fine in plain values; if you keep it in the same secret as the client secret, point `artefactflow.existingSecretClientIdKey` at its key.

The plugin exchanges those credentials for a short-lived access token and re-mints it shortly before expiry, so nothing has to be rotated for it to keep running. An already-minted bearer token is deliberately not accepted: it would expire long before a plugin that reconciles for weeks does.

```sh
kubectl create secret generic artefactflow-credentials -n argocd \
  --from-literal=client-secret='afsa_…'
```

By default the chart creates its own plugin-token secret, labelled `app.kubernetes.io/part-of: argocd` so the controller can read it, and points the ConfigMap at it with the `$secret:key` reference form. If your Argo CD is too old to resolve that form, put the key in `argocd-secret` instead and set:

```yaml
plugin:
  existingSecret: argocd-secret
  existingSecretKey: plugin.argocd-generator.token
  tokenRef: "$plugin.argocd-generator.token"
```

## Go templates in values

`applicationSets` entries are handed to Argo CD verbatim. Helm does not template values files, so `{{ .name }}`, `{{ .argocd_repo_url }}` and the `templatePatch` control flow reach the controller exactly as written, with no escaping, in this file or in yours.

## Values

| Key | Default | Description |
| --- | --- | --- |
| `image.repository` | `ghcr.io/artefactflow/argocd-generator` | Plugin image. |
| `image.tag` | `""` | Defaults to the chart `appVersion`; pin a release in production. |
| `artefactflow.apiUrl` | `https://api.artefactflow.app` | ArtefactFlow API base URL. |
| `artefactflow.clientId` | `""` | The service account's id, a UUID. Required unless it comes from a secret. |
| `artefactflow.clientSecret` / `.existingSecret` / `.existingSecretKey` | `""` / `""` / `client-secret` | The service account's client secret. One of the first two is required. |
| `artefactflow.existingSecretClientIdKey` | `""` | Read the client id from `existingSecret` under this key instead of from `clientId`. |
| `plugin.token` / `.existingSecret` / `.existingSecretKey` | `""` / `""` / `token` | Controller-to-plugin shared secret. One of the first two is required. |
| `plugin.tokenRef` | `""` | Override how the ConfigMap references the plugin token. |
| `plugin.port` | `4355` | Container port. |
| `plugin.requestTimeout` | `60` | Seconds the controller waits for a getparams response. |
| `plugin.allowEmpty` | `false` | Permit an empty parameter set. See the pruning note below. |
| `plugin.defaultNamespace` | `""` | Catch-all destination namespace. Unset makes an unusable namespace an error; see below. |
| `plugin.componentTypes` | `[]` | CycloneDX types that become Applications. Empty uses `application,container`. |
| `plugin.claimProperty` | `""` | Property naming what a component deploys. Empty uses `deploys-image`; see below. |
| `plugin.disableFold` | `false` | Render a claimed component as its own Application instead of folding it into the claimer. |
| `plugin.deployUnconfigured` | `false` | Render components carrying no `argocd_*` property, instead of treating them as inventory. |
| `replicaCount` | `1` | |
| `service.type` / `service.port` | `ClusterIP` / `4355` | |
| `resources` | 25m/32Mi → 250m/128Mi | |
| `networkPolicy.enabled` | `true` | Restrict ingress to the ApplicationSet controller. |
| `networkPolicy.controllerSelector` | `app.kubernetes.io/name: argocd-applicationset-controller` | Verify against your install: an unmatched selector silently blocks every reconcile. |
| `networkPolicy.controllerNamespaceSelector` | `{}` | Needed only when installing outside the controller's namespace. |
| `networkPolicy.apiEgressCIDRs` | `[]` | Narrow HTTPS egress; empty allows 443 anywhere. |
| `applicationSets` | one `production` entry | See `values.yaml` for the full shape. |
| `extraEnv`, `extraVolumes`, `extraVolumeMounts` | `[]` | For cases the above do not cover, such as a custom CA bundle. |
| `serviceAccount`, `podAnnotations`, `podLabels`, `nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints` | standard | |

### Namespaces

A component's destination namespace comes from `argocd_namespace`, falling back to the component's `group` only when that is already a valid namespace. If neither yields one, rendering fails and names the component.

That is deliberate. The obvious repairs (rewriting `com.acme.web` to `com-acme-web`, or defaulting to `default`) both produce a namespace nobody chose, and because the shipped sync policy sets `CreateNamespace=true` Argo CD would create it rather than reject it. The deployment would report Synced while running in the wrong place. Failing keeps the same guarantee as everything else here: the reconcile errors, and Argo CD keeps its last known-good set.

Set `plugin.defaultNamespace` if a catch-all really is what you want.

### Which components become Applications

An SBOM is an inventory: the complete set of what is inside a release. Argo CD needs a deployment topology: the set of root units to reconcile. They are different views of the same components, and three rules turn the first into the second.

**A Helm chart and the image it deploys are one workload.** A chart artefact carrying `deploys-image: pkg:docker/acme/checkout-service` claims that image. The chart becomes the Application; the image folds into it. Without this, both are rendered and the two Applications fight over the same resources. The fold is also what supplies the chart's `image.repository` and `image.tag`, which its own `pkg:helm/...` purl cannot, so no chart needs those restated by hand.

Several charts may claim one image (a shared sidecar, a job chart beside a service chart); that is not an error, and every claimer is named in the log. A claim pointing at something absent from the environment is likewise not fatal: the repository is still recoverable from the claim itself, only the tag is lost.

**A component with no `argocd_*` property at all is inventory, not a deployment.** An environment legitimately contains npm packages, mobile apps and SDKs that are not Argo CD Applications under any definition. They are skipped. A component with *some* `argocd_*` properties but not enough is a misconfiguration and still fails, which is what stops it being pruned.

**Types outside `plugin.componentTypes` are skipped**, `library` being the common case.

Every one of those exclusions is logged with the component name and the reason. That matters more than it looks: Argo CD treats the returned list as the complete desired state, so a component missing from it is a component it deletes. Run `argocd-gen generate --environment <env>` locally to see the same report on stderr before changing anything.

### Pruning

`plugin.allowEmpty` defaults to `false` on purpose. An empty parameter list tells the ApplicationSet controller that every generated Application is gone and it prunes them all, so the plugin refuses to return one: a failed resolve returns non-2xx, the reconcile errors, and Argo keeps its last known-good set. Only enable it if an environment with nothing deployed genuinely means "delete everything".
