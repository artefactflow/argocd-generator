# Configuration

argocd-generator turns what ArtefactFlow reports as deployed to an environment into Argo CD `Application` manifests. An SBOM tells the tool *what* is live (name, version, image) but not *how* to deploy it: the repository, chart or path, and values files. That deployment configuration is supplied as **properties** on the artefact and its version in ArtefactFlow, and the generator reads them.

This page is the reference for those properties. For how they fit into the whole flow (the API calls, the parameter objects, the rendered `Application`) see [how-it-works.md](how-it-works.md).

## Where deployment configuration lives

Set the `argocd_*` keys below as **properties** on the artefact (defaults for every version) and/or on a specific version (per-release overrides) in ArtefactFlow. A version-level property overrides the same key set at the artefact level. The resolved, merged set travels on each component of the SBOM version, so the generator reads everything it needs from a single SBOM document.

Property keys must match ArtefactFlow's property-name rules: letters, digits, `_` and `-` only, with no dots or slashes. The default key prefix is `argocd_`.

## Property keys

| Key | Purpose | Default when unset |
|-----|---------|--------------------|
| `argocd_repo_url` | Repository or Helm repository holding the manifests/chart | The component's `source`, then empty |
| `argocd_target_revision` | Git revision or chart version | `HEAD` |
| `argocd_path` | Path within a Git repository | empty |
| `argocd_chart` | Chart name in a Helm repository (use instead of `argocd_path`) | empty |
| `argocd_value_files` | Comma-separated list of values files; emitted as a list | empty list |
| `argocd_helm_parameters` | Comma-separated `name=value` pairs, emitted as Helm `parameters` entries | empty list |
| `argocd_namespace` | Destination namespace | The component's `group` when that is a valid namespace, otherwise an error |
| `argocd_project` | Argo CD project | `default` |

One further key is read, without the `argocd_` prefix:

| Key | Purpose | Default when unset |
|-----|---------|--------------------|
| `deploys-image` | Package URL of the component this one deploys, such as a Helm chart naming its image. The two render as one Application, and the claimer's `image_repository`/`image_tag` are derived from the claimed component. | none; the component is a deployment root in its own right |

It has no prefix on purpose: `argocd_*` says *how* to deploy something, whereas `deploys-image` records *what a thing is*, which is true whether or not Argo CD is involved. See [deployment-units.md](deployment-units.md).

`deploys-image` describes one chart deploying one image. For a **shared** chart that deploys many services, leave it unset and put `argocd_chart` on each service instead. See [one chart that deploys many workloads](deployment-units.md#one-chart-that-deploys-many-workloads).

Set `argocd_namespace` on anything you actually deploy: it is the one key with no safe default, and an unusable namespace is a hard error rather than a guess. See [Namespaces](#namespaces).

A component with **no** `argocd_*` key at all is treated as inventory rather than a deployment and is skipped, with a line in the exclusion report. One with some but not enough is a misconfiguration and fails.

Property values are strings of 1–1024 characters, so `argocd_value_files` is a comma-separated list rather than YAML.

Precedence for any key: version property, then artefact property, then the generator default, then whatever the ApplicationSet template hard-codes.

## Namespaces

`argocd_namespace` is the one property with no safe default, and the generator **fails** rather than guessing one.

The resolution order is:

1. `argocd_namespace`, if set. It is validated, so a typo fails here rather than at sync time.
2. The component's `group`, but only when that is already a valid namespace. For teams whose groups are flat names (`payments`) this is exactly right and saves a property on every artefact.
3. A configured default (`--default-namespace`, or `plugin.defaultNamespace` in the chart), if you set one.
4. Otherwise an error naming the component and the property to set.

Most real SBOMs carry a reverse-DNS `group` (`com.acme.web`), which is not a legal Kubernetes namespace, because dots are not allowed in an RFC 1123 label. The two obvious repairs are both worse than failing:

- **Rewriting dots to dashes** gives `com-acme-web`, a namespace nobody chose. The shipped sync policy sets `CreateNamespace=true`, so Argo CD would not reject it. It would *create* it. The deployment succeeds, reports Synced, and runs in the wrong place.
- **Falling back to `default`** does the same thing with more blast radius: production workloads land in `default` and look healthy.

A wrong success is worse than a failure. Failing keeps the guarantee the rest of the generator makes (the reconcile errors, Argo CD keeps its last known-good set, and nothing is pruned) and the operator gets a message they can act on:

```
component "admin-portal": no argocd_namespace property, and its group "com.acme.web"
is not a valid Kubernetes namespace; set argocd_namespace on the artefact or version
(or configure a default namespace)
```

Set a catch-all only if that is genuinely what you want:

```sh
argocd-gen generate --environment production --default-namespace sbom-apps
```

## Shared components

An environment usually holds several SBOMs, and the same component often appears in more than one of them. A service that is part of two product bills is still one deployable thing. Since the Application name is keyed on component identity, emitting it once per SBOM would put duplicate `metadata.name` entries into a single ApplicationSet.

Identical repeats are therefore collapsed to one parameter object. On a real environment this is not an edge case: 22 component entries across the SBOMs deployed to `production` resolve to 15 distinct identities.

If the repeats are *not* identical (the same component live twice in one environment at two different versions, or pointing at different destinations) that is a genuine conflict rather than a duplicate, and it fails:

```
component "checkout-service" is deployed to this environment by more than one SBOM
with conflicting configuration (image_tag: 1.5.0 vs 1.6.0); resolve it in ArtefactFlow,
or restrict the generator to a single SBOM
```

Silently picking one would deploy a version nobody asked for. Restricting the generator to a single SBOM is the escape hatch when the overlap is intentional: set `sbomName` alongside `environment` in the plugin generator's input parameters.

The CLI has no equivalent narrowing today. `--sbom` is a **separate mode** requiring `--version` (`generate --sbom acme-storefront-bom --version 1.3.0`), which renders that one version and never consults the environment; combined with `--environment` it is ignored rather than applied. To preview a single SBOM, use the `--sbom`/`--version` pair.

## Values files and Helm parameters

These are the two knobs most deployments actually need, and they work at both layers.

### Per component, from ArtefactFlow

```
argocd_value_files     = envs/production/checkout-service.yaml,common/defaults.yaml
argocd_helm_parameters = replicaCount=3,resources.limits.cpu=500m,ingress.enabled=true
```

becomes

```yaml
helm:
  valueFiles:
    - "envs/production/checkout-service.yaml"
    - "common/defaults.yaml"
  parameters:
    - name: image.repository
      value: "acme/checkout-service"
    - name: image.tag
      value: "1.5.0"
    - name: "replicaCount"
      value: "3"
    - name: "resources.limits.cpu"
      value: "500m"
    - name: "ingress.enabled"
      value: "true"
```

`image.repository` and `image.tag` are always emitted first for any component that has an image, and are not configurable: they are the whole point of generating from an SBOM, and are what makes a new release roll out. A container component's image comes from its own package URL; a Helm chart's comes from the component it claims with `deploys-image`, which is what gives a chart an image at all. Because Helm's later parameters win, a component *can* deliberately override them by naming them again in `argocd_helm_parameters`; nothing stops you, but prefer not to.

### Image tags that are not bare SemVer

`image_tag` is the component's version **exactly as ArtefactFlow stores it**, and ArtefactFlow validates a version as strict SemVer, so `v0.4.11` is rejected at the API with *"the 'version' must be a valid semantic version"*. So a registry that tags `v0.4.11`, `1.2.3-alpine` or `sha-abc123` cannot have that string round-trip through the artefact version.

The prefix or suffix belongs in the ApplicationSet template, not in a property, because it is the same for every component in an estate that adopts the convention:

```yaml
    - name: image.tag
      value: "v{{ .image_tag }}"
```

Doing it per component instead (`argocd_helm_parameters = image.tag=v0.4.11`, which wins because Helm's later parameters do) means re-stating the tag on every release, which is the one value that was supposed to come from the SBOM automatically. Keep it in the template.

### Two limits on property values

Two limits follow from properties being flat strings:

- **A value may not contain a comma**: that is the separator. Only the first `=` splits, so `ingress.annotations=a=b` is fine. Anything needing commas, lists, or nesting belongs in a values file.
- **A property *name* may not contain dots** (`^[a-zA-Z0-9_-]+$`), which is why the Helm parameter name lives in the value rather than the key. `argocd_helm_param_resources.limits.cpu` would be rejected by the API; `argocd_helm_parameters = resources.limits.cpu=500m` is not.

Names and values are emitted through the template's `quote`, so a value containing spaces or a colon cannot break the generated YAML.

### Organisation-wide, from the ApplicationSet

Anything every Application should get belongs in the ApplicationSet's `templatePatch` instead. It is the operator layer, it applies without touching a single artefact, and it changes without cutting new SBOM versions.

To give every Application a baseline values file, replace the conditional block in `templatePatch` with an unconditional one, listing the baseline first so per-component files still win:

```yaml
helm:
  valueFiles:
    - common/defaults.yaml
    {{- range .argocd_value_files }}
    - {{ . | quote }}
    {{- end }}
```

Static parameters work the same way: add them as literal entries alongside the image ones:

```yaml
  parameters:
    - name: global.clusterName
      value: prod-eu-west-1
    {{- if .image_repository }}
    - name: image.repository
      value: {{ .image_repository | quote }}
    ...
```

Rule of thumb: **if it differs per component, it is a property; if it is the same everywhere, it is the template.** Reaching for a property to set the same value on fifty artefacts is the wrong layer.

## Parameters the generator emits

Each component becomes one parameter object. Alongside the `argocd_*` keys above, the generator emits:

| Key | Description |
|-----|-------------|
| `name` | RFC 1123-safe Application name, with a stable hash suffix keyed on the component's BOM reference / artefact id |
| `rawName` | The component name as reported |
| `group` | The component group |
| `artefact_id` | The ArtefactFlow artefact id |
| `purl` | The component package URL |
| `purl_type` | The package URL type (for example `docker`, `oci`, `npm`) |
| `source` | The component source location |
| `image_repository` | Image repository. From the component's own package URL for a container (`docker`/`oci`) component; from the component named by `deploys-image` for a chart; empty otherwise |
| `image_tag` | The image version: the component's own for a container, the claimed component's for a chart |
| `argocd_helm_parameters` | List of `{name, value}` objects from the property of the same name; empty list when unset |

Because the generator always emits every key with a default, an ApplicationSet template can safely use `goTemplateOptions: ["missingkey=error"]`.

## Two layers of configuration

1. **Operator layer**: the ApplicationSet `template` fixes the overall shape and any organisation-wide values (project, sync policy, a house chart). See [`deploy/applicationset.yaml`](../deploy/applicationset.yaml).
2. **Per-artefact layer**: the `argocd_*` properties above, resolved onto each component, override into that template.

Anything that must change without cutting a new SBOM version belongs in the operator layer, because a released SBOM version is immutable, so its resolved properties are fixed at release time.

## Example

Properties on version `1.5.0` of an artefact:

```
argocd_repo_url        = https://git.example.com/deploy/helm-charts
argocd_path            = charts/generic-service
argocd_value_files     = envs/production/checkout-service.yaml,common/defaults.yaml
argocd_helm_parameters = replicaCount=3
argocd_namespace       = payments
```

The generator emits, for that component:

```json
{
  "name": "checkout-service-e5e6295c",
  "rawName": "checkout-service",
  "group": "com.acme.payments",
  "image_repository": "acme/checkout-service",
  "image_tag": "1.5.0",
  "argocd_repo_url": "https://git.example.com/deploy/helm-charts",
  "argocd_target_revision": "HEAD",
  "argocd_path": "charts/generic-service",
  "argocd_chart": "",
  "argocd_value_files": ["envs/production/checkout-service.yaml", "common/defaults.yaml"],
  "argocd_helm_parameters": [{"name": "replicaCount", "value": "3"}],
  "argocd_namespace": "payments",
  "argocd_project": "default"
}
```
