package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/artefactflow/argocd-generator/internal/sbom"
)

// Notice records something the renderer decided about a component that is not visible in the parameter list itself, most importantly that a component was deliberately not rendered as an Application.
//
// This type exists because of the rule the rest of the generator keeps: Argo CD treats the returned list as the complete desired state, so a component missing from it is a component it will delete. Every mechanism that removes a component therefore has to say so out loud. A silent filter is indistinguishable from a forgotten property until an Application disappears from production.
type Notice struct {
	// Name is the component the notice is about, or the claim target for ReasonClaimTargetAbsent.
	Name string `json:"name"`
	// PURL identifies the component independently of its display name.
	PURL string `json:"purl,omitempty"`
	// Reason is one of the Reason* constants.
	Reason string `json:"reason"`
	// Detail carries the specifics: which type was filtered, which component claimed this one.
	Detail string `json:"detail,omitempty"`
	// Excluded is true when the component was left out of the parameter list. False marks an advisory about a component that was still rendered.
	Excluded bool `json:"excluded"`
}

const (
	// ReasonComponentType: the component's CycloneDX type is not in Config.ComponentTypes.
	ReasonComponentType = "component-type"
	// ReasonNoDeploymentConfig: the component carries no argocd_* properties at all, so it is inventory rather than a deployment. See Config.DeployUnconfigured.
	ReasonNoDeploymentConfig = "no-deployment-config"
	// ReasonFolded: another component claimed this one via the claim property, so the claimer is the deployment root and this component is part of it.
	ReasonFolded = "folded-into"
	// ReasonClaimTargetAbsent: a component claims something that is not in this environment. Advisory, not an exclusion: the claimer is still rendered, with the image repository derived from the claim's own PURL and no tag.
	ReasonClaimTargetAbsent = "claim-target-absent"
	// ReasonUnclaimedPair: a chart and an image look like a pair, but neither claims the other, so both will deploy. Advisory.
	ReasonUnclaimedPair = "unclaimed-pair"
	// ReasonClaimPropertyTypo: a property is spelled almost like the claim property, so it is being silently ignored. Advisory.
	ReasonClaimPropertyTypo = "claim-property-typo"
)

func (n Notice) String() string {
	s := n.Name
	if n.PURL != "" {
		s += " (" + n.PURL + ")"
	}
	s += ": " + n.Reason
	if n.Detail != "" {
		s += " " + n.Detail
	}
	return s
}

// claimKey normalises a PURL to the identity used to match a claim against a component. Version, qualifiers and subpath are dropped, because a chart names the image it deploys without pinning a tag. The tag comes from the component, which is the point of deriving it. Returns "" for anything that is not a PURL.
func claimKey(purl string) string {
	typ, path := parsePURL(purl)
	if typ == "" || path == "" {
		return ""
	}
	return typ + "/" + path
}

// checkResolved rejects a component the API returned without its catalog projection.
//
// ArtefactFlow resolves each component's artefact to fill in name, type and purl; when that resolution fails it skips the component and returns the bare {artefact_id, version} reference instead of failing. Rendering that is not possible, and worse, an unnamed, untyped component is silently dropped by the type filter, so a whole environment can come back empty, which is the one output that prunes every Application. Failing here turns a silent upstream degradation into a visible error.
func checkResolved(c sbom.Component) error {
	if c.Name != "" || c.Type != "" || c.PURL != "" {
		return nil
	}
	ref := c.ArtefactID
	if ref == "" {
		ref = "(no artefact_id)"
	}
	return fmt.Errorf("component %s@%s was returned without its catalog projection (no name, type or purl): ArtefactFlow could not resolve the artefact, so the environment's component list is incomplete; retry once the artefact service is reachable", ref, c.Version)
}

// hasDeploymentConfig reports whether a component carries any argocd_* property of its own.
//
// The test is deliberately on the raw property list rather than on the rendered parameters: repo_url falls back to the component's source and several other keys have defaults, so after defaulting almost everything looks configured. What distinguishes a deployment from inventory is that somebody wrote deployment configuration onto it.
func hasDeploymentConfig(cfg Config, c sbom.Component) bool {
	for _, p := range c.Properties {
		if strings.HasPrefix(p.Name, cfg.Prefix) && p.Value != "" {
			return true
		}
	}
	return false
}

// claimsOf indexes the claim property across a set of components: claim key -> names of the components claiming it, sorted so the reported detail is stable between runs.
//
// A component claiming its own PURL is ignored rather than treated as an error; it is a data mistake that would otherwise remove the component from the set entirely, which is the outcome this whole mechanism exists to prevent.
func claimsOf(cfg Config, components []sbom.Component) (map[string][]string, error) {
	claims := map[string][]string{}
	for _, c := range components {
		v, ok := c.Prop(cfg.ClaimProperty)
		if !ok || v == "" {
			continue
		}
		key := claimKey(v)
		if key == "" {
			return nil, fmt.Errorf("component %q: %s is %q, which is not a package URL; the claim must name the component it deploys, for example pkg:docker/acme/checkout-service", c.Name, cfg.ClaimProperty, v)
		}
		if key == claimKey(c.PURL) {
			continue
		}
		claims[key] = append(claims[key], c.Name)
	}
	// Several charts legitimately deploy one image: a shared sidecar, or a job chart alongside a service chart. That is not an error: the image is not a root either way, and both claimers still render. Sorting keeps the "folded into a, b" detail deterministic.
	for k := range claims {
		sort.Strings(claims[k])
	}
	return claims, nil
}

// suspectedPairs finds chart/image pairs that nobody linked.
//
// The exclusion report explains what was removed. The opposite failure is quieter: a chart that should claim an image but does not removes nothing, so nothing is reported, and both components deploy: exactly the double deployment the claim exists to prevent. This is the only remaining way for that outcome to arrive without a word.
//
// Matching is deliberately narrow: a Helm component and a container component whose names differ only by a "chart" prefix or suffix. A chart whose image is not in the same environment is entirely normal, so warning about every unclaimed chart would fire constantly and teach operators to skim past the report, which would cost more than it saves.
func suspectedPairs(cfg Config, candidates []sbom.Component, claims map[string][]string) []Notice {
	byStem := map[string][]sbom.Component{}
	for _, c := range candidates {
		typ, _ := parsePURL(c.PURL)
		switch typ {
		case "helm", "docker", "oci":
			byStem[chartStem(c.Name)] = append(byStem[chartStem(c.Name)], c)
		}
	}

	var out []Notice
	for _, group := range byStem {
		for _, chart := range group {
			if typ, _ := parsePURL(chart.PURL); typ != "helm" {
				continue
			}
			if v, ok := chart.Prop(cfg.ClaimProperty); ok && v != "" {
				continue
			}
			for _, image := range group {
				if typ, _ := parsePURL(image.PURL); typ == "helm" {
					continue
				}
				// Something else may already have claimed the image, in which case it is not orphaned and this chart is presumably unrelated to it.
				if len(claims[claimKey(image.PURL)]) > 0 {
					continue
				}
				out = append(out, Notice{
					Name:   chart.Name,
					PURL:   chart.PURL,
					Reason: ReasonUnclaimedPair,
					Detail: fmt.Sprintf("looks like it deploys %s (%s); set %s on the chart or both will deploy", image.Name, image.PURL, cfg.ClaimProperty),
				})
			}
		}
	}
	return out
}

// chartStem reduces a component name to the identity a chart and its image share, by removing a leading or trailing "chart" and any separator around it. "checkout-service-chart" and "checkout-service" both reduce to "checkout-service".
func chartStem(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	for _, suffix := range []string{"-chart", "_chart", ".chart", "chart"} {
		if trimmed, ok := strings.CutSuffix(s, suffix); ok && trimmed != "" {
			return strings.Trim(trimmed, "-_.")
		}
	}
	for _, prefix := range []string{"chart-", "chart_", "chart."} {
		if trimmed, ok := strings.CutPrefix(s, prefix); ok && trimmed != "" {
			return strings.Trim(trimmed, "-_.")
		}
	}
	return s
}

// misspelledClaims reports properties that are almost the claim property.
//
// A misspelled property is simply an unread property, indistinguishable from the outside from never having set one. `deploys_image` is the obvious slip, since ArtefactFlow property names allow both separators.
func misspelledClaims(cfg Config, candidates []sbom.Component) []Notice {
	want := normaliseKey(cfg.ClaimProperty)
	var out []Notice
	for _, c := range candidates {
		for _, p := range c.Properties {
			if p.Name == cfg.ClaimProperty || normaliseKey(p.Name) != want {
				continue
			}
			out = append(out, Notice{
				Name:   c.Name,
				PURL:   c.PURL,
				Reason: ReasonClaimPropertyTypo,
				Detail: fmt.Sprintf("property %q looks like %q but is not read", p.Name, cfg.ClaimProperty),
			})
		}
	}
	return out
}

// normaliseKey strips case and the separators ArtefactFlow property names allow, so deploys_image, deploys-image and deploysImage all compare equal.
func normaliseKey(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r != '-' && r != '_' && r != '.' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// deployedImage resolves what a claim points at: the repository and tag to give the claiming component.
//
// The repository comes from the claim's own PURL, so a claim that names a component absent from this environment still yields a usable repository, and only the tag is lost. present reports whether the claimed component was actually found, which the caller turns into an advisory rather than an error.
func deployedImage(byKey map[string]sbom.Component, claimValue string) (repository, tag string, present bool) {
	key := claimKey(claimValue)
	if key == "" {
		return "", "", false
	}
	if c, ok := byKey[key]; ok {
		return imageRepositoryFromPURL(c.PURL), c.Version, true
	}
	return imageRepositoryFromPURL(claimValue), "", false
}
