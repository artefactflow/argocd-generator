package afclient

import (
	"context"
	"fmt"
	"net/url"
	"regexp"

	"github.com/artefactflow/argocd-generator/internal/sbom"
)

// Minimal wire types: only the fields the generator reads. Unknown fields are ignored by encoding/json, so upstream additions do not break these.

type environmentsPage struct {
	Metadata pageMetadata  `json:"metadata"`
	Items    []Environment `json:"environments"`
}

// Environment is one environment resource.
type Environment struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type deploymentsPage struct {
	Metadata    pageMetadata `json:"metadata"`
	Deployments []Deployment `json:"deployments"`
}

// Deployment is one active deployment: which SBOM version is live in an environment. SbomName is the denormalised, URL-safe SBOM name used to address the version document.
type Deployment struct {
	SbomID          string `json:"sbom_id"`
	SbomName        string `json:"sbom_name"`
	VersionValue    string `json:"version_value"`
	EnvironmentSlug string `json:"environment_slug"`
	Status          string `json:"status"`
}

type pageMetadata struct {
	HasMore    bool   `json:"has_more"`
	NextCursor string `json:"next_cursor"`
}

// resourceIDRE is the API's ResourceId: a 36-character lowercase hyphenated UUID, the form of every identifier it issues, a service account's client id and an environment id included. Only that spelling is accepted, so an uppercase or unhyphenated UUID is not one.
var resourceIDRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// IsResourceID reports whether s is spelled as an ArtefactFlow resource id.
func IsResourceID(s string) bool {
	return resourceIDRE.MatchString(s)
}

// ResolveEnvironmentID turns an operator-supplied environment reference into an environment id. A resource id is accepted as-is; anything else is treated as a slug and matched against the environment list.
func (c *Client) ResolveEnvironmentID(ctx context.Context, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("environment reference is empty")
	}
	if IsResourceID(ref) {
		return ref, nil
	}

	cursor := ""
	for page := 0; page < 1000; page++ { // hard cap guards against a broken cursor loop
		q := url.Values{}
		q.Set("limit", "100")
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var resp environmentsPage
		if err := c.getJSON(ctx, "/v1/environments", q, &resp); err != nil {
			return "", fmt.Errorf("list environments: %w", err)
		}
		for _, e := range resp.Items {
			if e.Slug == ref {
				return e.ID, nil
			}
		}
		if !resp.Metadata.HasMore || resp.Metadata.NextCursor == "" {
			break
		}
		cursor = resp.Metadata.NextCursor
	}
	return "", fmt.Errorf("no environment found with slug %q", ref)
}

// ActiveDeployments returns the currently active deployments in an environment, one per live SBOM.
func (c *Client) ActiveDeployments(ctx context.Context, envID string) ([]Deployment, error) {
	var resp deploymentsPage
	path := "/v1/environments/" + url.PathEscape(envID) + "/deployments/active"
	if err := c.getJSON(ctx, path, nil, &resp); err != nil {
		return nil, fmt.Errorf("list active deployments for %s: %w", envID, err)
	}
	return resp.Deployments, nil
}

// GetSBOMVersion fetches and tolerantly parses one SBOM version document.
func (c *Client) GetSBOMVersion(ctx context.Context, sbomName, versionValue string) (*sbom.Version, error) {
	path := "/v1/sboms/" + url.PathEscape(sbomName) + "/versions/" + url.PathEscape(versionValue)
	body, err := c.getRaw(ctx, c.baseURL+path)
	if err != nil {
		return nil, fmt.Errorf("get sbom version %s@%s: %w", sbomName, versionValue, err)
	}
	v, err := sbom.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("parse sbom version %s@%s: %w", sbomName, versionValue, err)
	}
	return v, nil
}
