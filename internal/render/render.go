// Package render turns resolved SBOM components into the flat parameter objects an Argo CD ApplicationSet plugin generator returns under output.parameters. Each parameter object is rendered by the operator's ApplicationSet template into one Application. The generator stays deliberately dumb: it reads the argocd_* properties already merged onto each component and fills defaults, so all deployment shape lives in the operator's template.
package render

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/artefactflow/argocd-generator/internal/sbom"
)

// Property key convention. The prefix is configurable; these are the defaults.
const (
	keyRepoURL        = "repo_url"
	keyTargetRevision = "target_revision"
	keyPath           = "path"
	keyChart          = "chart"
	keyValueFiles     = "value_files"
	keyHelmParameters = "helm_parameters"
	keyNamespace      = "namespace"
	keyProject        = "project"
)

// Config controls how components are selected and defaulted. A zero Config is usable via Defaults().
type Config struct {
	// Prefix on argocd_* property keys (default "argocd_").
	Prefix string
	// ComponentTypes to include (default {"application","container"}). Empty means include every type.
	ComponentTypes []string
	// Default Argo project when a component sets none (default "default").
	DefaultProject string
	// Default target revision when a component sets none (default "HEAD").
	DefaultTargetRevision string
	// DefaultRepoURL used when a component sets neither repo_url nor a source (default ""). A component's own source is preferred over this.
	DefaultRepoURL string
	// DefaultNamespace is the destination namespace for a component that sets no namespace property and whose group is not a usable namespace. Empty (the default) makes that combination an error instead. See resolveNamespace.
	DefaultNamespace string
	// ClaimProperty names the property by which one component declares the component it deploys (default "deploys-image"). It is not under Prefix: a Helm chart deploys its image whether or not Argo CD is involved, so the relationship is a fact about the artefact rather than deployment configuration.
	ClaimProperty string
	// DisableFold keeps a claimed component as its own Application instead of folding it into the component that claims it. Off by default: a chart and the image it deploys are one workload, and rendering both makes two Applications fight over it.
	DisableFold bool
	// DeployUnconfigured renders components that carry no argocd_* property at all, instead of treating them as inventory. Off by default, because an environment holds npm packages, mobile apps and SDKs that are not Argo CD Applications under any definition, and inventing a destination for them deploys something nobody asked for. Every skipped component is reported either way.
	DeployUnconfigured bool
}

// Defaults returns a Config with the standard convention applied.
func Defaults() Config {
	return Config{
		Prefix:                "argocd_",
		ComponentTypes:        []string{"application", "container"},
		DefaultProject:        "default",
		DefaultTargetRevision: "HEAD",
		ClaimProperty:         defaultClaimProperty,
	}
}

// defaultClaimProperty is the property ArtefactFlow already carries on a Helm chart artefact to name the image that chart deploys.
const defaultClaimProperty = "deploys-image"

func (c Config) withDefaults() Config {
	if c.Prefix == "" {
		c.Prefix = "argocd_"
	}
	if c.ComponentTypes == nil {
		c.ComponentTypes = []string{"application", "container"}
	}
	if c.DefaultProject == "" {
		c.DefaultProject = "default"
	}
	if c.DefaultTargetRevision == "" {
		c.DefaultTargetRevision = "HEAD"
	}
	if c.ClaimProperty == "" {
		c.ClaimProperty = defaultClaimProperty
	}
	return c
}

// Param is one output parameter object. Values are strings, string lists, or lists of name/value objects, so the document round-trips cleanly to JSON for both the plugin response and the CLI.
type Param map[string]any

// HelmParameter is one entry for an Application's helm.parameters. It is emitted as a list rather than a map so the ApplicationSet template can range over it in order, and because Argo CD's own schema is a list.
type HelmParameter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Versions renders the components of one or more SBOM versions into a flat, deterministically ordered parameter list, together with a notice for every component it left out and every derivation worth knowing about. A component shared by several of the SBOMs is emitted once.
//
// Three things remove a component from the list, and all three are reported rather than applied silently: its CycloneDX type is not selected, it carries no deployment configuration at all (inventory, not a deployment), or another component claimed it and is therefore the deployment root. Nothing else drops a component: an unrenderable one is an error.
//
// It fails rather than emitting something it cannot render correctly: a component the API returned unresolved, an unusable destination namespace (see resolveNamespace), or the same component deployed twice to one environment with conflicting configuration. All follow the rule the rest of the generator keeps: a wrong Application is worse than no answer, because a wrong answer deploys.
func Versions(cfg Config, versions ...*sbom.Version) ([]Param, []Notice, error) {
	cfg = cfg.withDefaults()
	typeSet := map[string]bool{}
	for _, t := range cfg.ComponentTypes {
		typeSet[t] = true
	}

	// Catch a bad operator-supplied default once, here, rather than once per component that happens to need it.
	if cfg.DefaultNamespace != "" && !validNamespace(cfg.DefaultNamespace) {
		return nil, nil, fmt.Errorf("configured default namespace %q is not a valid Kubernetes namespace", cfg.DefaultNamespace)
	}

	var notices []Notice

	// Pass 1: flatten every version into the set of components that are candidates to become an Application, recording why each rejected one was rejected. Claims are resolved against candidates only: a chart that was itself filtered out must not fold away the image it deploys, or the workload would vanish from the set entirely.
	var candidates []sbom.Component
	for _, v := range versions {
		if v == nil {
			continue
		}
		for _, c := range v.Components {
			if err := checkResolved(c); err != nil {
				return nil, nil, err
			}
			if len(typeSet) > 0 && !typeSet[c.Type] {
				notices = append(notices, Notice{Name: c.Name, PURL: c.PURL, Reason: ReasonComponentType, Detail: c.Type, Excluded: true})
				continue
			}
			if !cfg.DeployUnconfigured && !hasDeploymentConfig(cfg, c) {
				notices = append(notices, Notice{Name: c.Name, PURL: c.PURL, Reason: ReasonNoDeploymentConfig, Excluded: true})
				continue
			}
			candidates = append(candidates, c)
		}
	}

	// Pass 2: index the candidates by identity and collect the claims between them.
	byKey := make(map[string]sbom.Component, len(candidates))
	for _, c := range candidates {
		if k := claimKey(c.PURL); k != "" {
			byKey[k] = c
		}
	}
	claims := map[string][]string{}
	if !cfg.DisableFold {
		var err error
		if claims, err = claimsOf(cfg, candidates); err != nil {
			return nil, nil, err
		}
		// Advisories about claims that should exist and do not. Nothing is excluded by either, but a chart that fails to claim its image deploys twice, and that outcome would otherwise arrive with no mention anywhere.
		notices = append(notices, suspectedPairs(cfg, candidates, claims)...)
		notices = append(notices, misspelledClaims(cfg, candidates)...)
	}

	// Pass 3: render what is left. An environment usually holds several SBOMs, and a shared component (a service that is part of more than one product bill) appears in each of them. Those are one deployable thing, not N, and the Application name is keyed on component identity, so emitting them all would put duplicate metadata.name entries in one ApplicationSet.
	var out []Param
	seen := map[string]Param{}
	folded := map[string]bool{}
	for _, c := range candidates {
		if claimers, ok := claims[claimKey(c.PURL)]; ok {
			// Not a silent drop: this component is deployed, by the component that claimed it, and the notice names which one.
			if key := claimKey(c.PURL); !folded[key] {
				folded[key] = true
				notices = append(notices, Notice{Name: c.Name, PURL: c.PURL, Reason: ReasonFolded, Detail: strings.Join(claimers, ", "), Excluded: true})
			}
			continue
		}

		p, err := renderComponent(cfg, c)
		if err != nil {
			return nil, nil, err
		}
		if !cfg.DisableFold {
			notices = append(notices, applyClaim(cfg, c, byKey, p)...)
		}

		name := p["name"].(string)
		if prev, dup := seen[name]; dup {
			// Identical repeats collapse. Differing ones are a genuine conflict, the same component live twice in one environment with two different versions or destinations, and picking one arbitrarily would deploy a version nobody asked for.
			if diff := diffKeys(prev, p); len(diff) > 0 {
				return nil, nil, fmt.Errorf("component %q is deployed to this environment by more than one SBOM with conflicting configuration (%s); resolve it in ArtefactFlow, or restrict the generator to a single SBOM", c.Name, describeDiff(prev, p, diff))
			}
			continue
		}
		seen[name] = p
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i]["name"].(string) < out[j]["name"].(string)
	})
	notices = dedupeNotices(notices)
	sortNotices(notices)
	return out, notices, nil
}

// applyClaim fills in the image a claiming component deploys.
//
// A chart's own PURL is pkg:helm/..., so image_repository comes out empty even though deploying the chart is precisely how the image reaches the cluster, and an ApplicationSet template then has nothing to set image.repository from. The claim names the component the chart deploys, which is where those values come from instead of being restated by hand on every chart.
//
// Only the top-level image_repository/image_tag are set, deliberately: the shipped template already renders those into Helm parameters, so also injecting them into argocd_helm_parameters would emit each parameter twice. A component that sets image.repository explicitly still wins, because the template ranges over argocd_helm_parameters after the derived pair.
func applyClaim(cfg Config, c sbom.Component, byKey map[string]sbom.Component, p Param) []Notice {
	claimValue, ok := c.Prop(cfg.ClaimProperty)
	if !ok || claimValue == "" {
		return nil
	}
	repository, tag, present := deployedImage(byKey, claimValue)
	if repository == "" {
		return nil
	}

	var notices []Notice
	if !present {
		// The claim is still honoured (the repository is recoverable from the claim's own PURL) but nobody can supply the tag, and a claim pointing outside the environment usually means the image's SBOM is not deployed here.
		notices = append(notices, Notice{Name: claimValue, PURL: claimValue, Reason: ReasonClaimTargetAbsent, Detail: "claimed by " + c.Name + "; image tag could not be derived"})
	}

	p["image_repository"] = repository
	if tag != "" {
		p["image_tag"] = tag
	}
	return notices
}

// dedupeNotices collapses repeats. A component shared by several of an environment's SBOMs is skipped once per SBOM it appears in, but it is one component and one decision, and reporting it three times reads as three problems.
func dedupeNotices(in []Notice) []Notice {
	seen := make(map[Notice]bool, len(in))
	out := in[:0]
	for _, n := range in {
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// sortNotices orders the report deterministically: exclusions first, since those are what change the desired state, then by reason and name.
func sortNotices(n []Notice) {
	sort.SliceStable(n, func(i, j int) bool {
		if n[i].Excluded != n[j].Excluded {
			return n[i].Excluded
		}
		if n[i].Reason != n[j].Reason {
			return n[i].Reason < n[j].Reason
		}
		return n[i].Name < n[j].Name
	})
}

func renderComponent(cfg Config, c sbom.Component) (Param, error) {
	get := func(key string) (string, bool) { return c.Prop(cfg.Prefix + key) }
	def := func(key, fallback string) string {
		if v, ok := get(key); ok && v != "" {
			return v
		}
		return fallback
	}

	repoURL := def(keyRepoURL, firstNonEmpty(c.Source, cfg.DefaultRepoURL))

	nsProp, _ := get(keyNamespace)
	namespace, err := resolveNamespace(cfg, nsProp, c)
	if err != nil {
		return nil, err
	}

	var valueFiles []string
	if v, ok := get(keyValueFiles); ok {
		valueFiles = splitList(v)
	}
	if valueFiles == nil {
		valueFiles = []string{}
	}

	var helmParams []HelmParameter
	if v, ok := get(keyHelmParameters); ok {
		helmParams = parseHelmParameters(v)
	}
	if helmParams == nil {
		helmParams = []HelmParameter{}
	}

	purlType, _ := parsePURL(c.PURL)

	return Param{
		"name":                         k8sName(c.Name, firstNonEmpty(c.BOMRef, c.ArtefactID, c.Name)),
		"rawName":                      c.Name,
		"group":                        c.Group,
		"artefact_id":                  c.ArtefactID,
		"purl":                         c.PURL,
		"purl_type":                    purlType,
		"source":                       c.Source,
		"image_repository":             imageRepositoryFromPURL(c.PURL),
		"image_tag":                    c.Version,
		cfg.Prefix + keyRepoURL:        repoURL,
		cfg.Prefix + keyTargetRevision: def(keyTargetRevision, cfg.DefaultTargetRevision),
		cfg.Prefix + keyPath:           def(keyPath, ""),
		cfg.Prefix + keyChart:          def(keyChart, ""),
		cfg.Prefix + keyValueFiles:     valueFiles,
		cfg.Prefix + keyHelmParameters: helmParams,
		cfg.Prefix + keyNamespace:      namespace,
		cfg.Prefix + keyProject:        def(keyProject, cfg.DefaultProject),
	}, nil
}

// diffKeys returns the parameter keys whose values differ between two renderings of the same component, in a stable order so the error message does not change between runs.
func diffKeys(a, b Param) []string {
	var out []string
	for k, av := range a {
		if !reflect.DeepEqual(av, b[k]) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// describeDiff renders the differing keys as `key: x vs y`, so the operator sees which value is in conflict rather than being told only that something is.
func describeDiff(a, b Param, keys []string) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s: %v vs %v", k, a[k], b[k]))
	}
	return strings.Join(parts, "; ")
}

// namespaceRE is the RFC 1123 label form Kubernetes requires of a namespace name.
var namespaceRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

const maxNamespaceLen = 63

// resolveNamespace picks a component's destination namespace, and refuses to invent one.
//
// The component's group is used when it already is a valid namespace, because for teams whose groups are flat names that is exactly right and saves setting a property on every artefact. But group is usually reverse-DNS (`com.acme.web`), and the tempting repairs are both worse than failing:
//
//   - Rewriting dots to dashes yields `com-acme-web`, a namespace nobody chose. The shipped sync policy sets CreateNamespace=true, so Argo CD would not reject it. It would create it, and the deployment would silently succeed in the wrong place while looking healthy.
//   - Falling back to `default` does the same thing with more blast radius: production workloads land in `default` and report Synced.
//
// A wrong success is worse than a failure here. Failing keeps the guarantee the rest of the generator makes (the reconcile errors, Argo CD keeps its last known-good set, and nothing is pruned) and the message names the component and the property to set. An operator who genuinely wants a blanket fallback opts into it with Config.DefaultNamespace.
//
// An explicitly set property is validated too, so a typo fails here rather than at sync time.
func resolveNamespace(cfg Config, prop string, c sbom.Component) (string, error) {
	if prop != "" {
		if !validNamespace(prop) {
			return "", fmt.Errorf("component %q: %s%s is %q, which is not a valid Kubernetes namespace (lowercase letters, digits and dashes, at most %d characters)", c.Name, cfg.Prefix, keyNamespace, prop, maxNamespaceLen)
		}
		return prop, nil
	}
	if validNamespace(c.Group) {
		return c.Group, nil
	}
	if cfg.DefaultNamespace != "" {
		return cfg.DefaultNamespace, nil
	}
	if c.Group == "" {
		return "", fmt.Errorf("component %q: no %s%s property and the component has no group to fall back to; set %s%s on the artefact or version", c.Name, cfg.Prefix, keyNamespace, cfg.Prefix, keyNamespace)
	}
	return "", fmt.Errorf("component %q: no %s%s property, and its group %q is not a valid Kubernetes namespace; set %s%s on the artefact or version (or configure a default namespace)", c.Name, cfg.Prefix, keyNamespace, c.Group, cfg.Prefix, keyNamespace)
}

func validNamespace(s string) bool {
	return s != "" && len(s) <= maxNamespaceLen && namespaceRE.MatchString(s)
}

var invalidName = regexp.MustCompile(`[^a-z0-9-]+`)

// maxNameBase bounds the sanitised base name. With the "-" + 8-char hash suffix the emitted name is at most 53 characters, so an ApplicationSet template that prefixes it (for example "sbom-{{ .name }}") still stays within the 63-char limit that Argo CD's app.kubernetes.io/instance tracking label imposes.
const maxNameBase = 44

// k8sName produces an RFC 1123 label-safe, collision-resistant name. Component names and PURLs contain characters illegal in resource names, and two components can sanitise to the same string, so a short stable hash of uniq is appended. Keying the hash on a stable identifier (bom-ref / artefact_id) keeps the name steady across reconciles unless that identity actually changes.
func k8sName(name, uniq string) string {
	s := invalidName.ReplaceAllString(strings.ToLower(name), "-")
	s = strings.Trim(s, "-")
	if s == "" {
		s = "component"
	}
	if len(s) > maxNameBase {
		s = strings.Trim(s[:maxNameBase], "-")
	}
	h := sha256.Sum256([]byte(uniq))
	return fmt.Sprintf("%s-%s", s, hex.EncodeToString(h[:])[:8])
}

// parseHelmParameters reads a comma-separated list of name=value pairs into ordered Helm parameters, so a component can set chart values the ApplicationSet template does not know about ahead of time.
//
// Only the first `=` splits, so a value may contain them (`ingress.annotations=a=b`). A value may not contain a comma: ArtefactFlow properties are flat strings capped at 1024 characters, and inventing a quoting syntax on top of that would be worse than the alternative, which is to put anything that complex in a values file. Entries with an empty name are dropped rather than emitted as a parameter Argo CD would reject.
func parseHelmParameters(s string) []HelmParameter {
	var out []HelmParameter
	for _, p := range strings.Split(s, ",") {
		name, value, found := strings.Cut(p, "=")
		name = strings.TrimSpace(name)
		if !found || name == "" {
			continue
		}
		out = append(out, HelmParameter{Name: name, Value: strings.TrimSpace(value)})
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
