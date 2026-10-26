// Package generate orchestrates the ArtefactFlow API into the flat parameter list that drives an Argo CD ApplicationSet. It ties the afclient calls together and enforces the correctness rule that matters most here: the environment's deployment set is the source of truth for what should be live, so a partial result must never be returned. Any failure to resolve or fetch a member SBOM fails the whole operation, so a downstream consumer keeps its last known-good set instead of pruning apps for the SBOMs that failed to load.
package generate

import (
	"context"
	"fmt"

	"github.com/artefactflow/argocd-generator/internal/afclient"
	"github.com/artefactflow/argocd-generator/internal/render"
	"github.com/artefactflow/argocd-generator/internal/sbom"
)

// SBOMFetcher is the subset of the client the orchestration needs. It keeps the package testable without a live API.
type SBOMFetcher interface {
	ResolveEnvironmentID(ctx context.Context, ref string) (string, error)
	ActiveDeployments(ctx context.Context, envID string) ([]afclient.Deployment, error)
	GetSBOMVersion(ctx context.Context, sbomName, versionValue string) (*sbom.Version, error)
}

// FromEnvironment resolves every SBOM live in an environment and returns their version documents. See FromEnvironmentSBOM for the parameters and guarantees; this includes all live SBOMs.
func FromEnvironment(ctx context.Context, c SBOMFetcher, envRef string) ([]*sbom.Version, error) {
	return FromEnvironmentSBOM(ctx, c, envRef, "")
}

// FromEnvironmentSBOM resolves the SBOMs live in an environment and returns their version documents. envRef is a slug or an environment id. When sbomNameFilter is non-empty, only the active deployment of that SBOM is included. It fails loudly if any included member cannot be resolved or fetched, never a partial set. An environment with no matching active deployments returns an empty slice and no error; callers that must not prune on empty (the plugin server) guard that case.
func FromEnvironmentSBOM(ctx context.Context, c SBOMFetcher, envRef, sbomNameFilter string) ([]*sbom.Version, error) {
	envID, err := c.ResolveEnvironmentID(ctx, envRef)
	if err != nil {
		return nil, err
	}
	deployments, err := c.ActiveDeployments(ctx, envID)
	if err != nil {
		return nil, err
	}

	versions := make([]*sbom.Version, 0, len(deployments))
	for _, d := range deployments {
		// The active endpoint returns only active deployments, but guard against a superseded/removed record slipping in so we never render something that is not actually live.
		if d.Status != "" && d.Status != "active" {
			continue
		}
		if sbomNameFilter != "" && d.SbomName != sbomNameFilter {
			continue
		}
		if d.SbomName == "" {
			return nil, fmt.Errorf("active deployment for sbom_id %s has no sbom_name; cannot resolve version document", d.SbomID)
		}
		v, err := c.GetSBOMVersion(ctx, d.SbomName, d.VersionValue)
		if err != nil {
			// Surface, never drop: a missing app in the generated set is a failed deployment.
			return nil, fmt.Errorf("environment %q: %w", envRef, err)
		}
		versions = append(versions, v)
	}
	return versions, nil
}

// FromSBOM fetches a single SBOM version document.
func FromSBOM(ctx context.Context, c SBOMFetcher, sbomName, versionValue string) (*sbom.Version, error) {
	return c.GetSBOMVersion(ctx, sbomName, versionValue)
}

// Environment renders every component live in an environment into Argo parameters, ordered deterministically across all member SBOMs, plus the notices explaining every component that was left out.
func Environment(ctx context.Context, c SBOMFetcher, cfg render.Config, envRef string) ([]render.Param, []render.Notice, error) {
	return EnvironmentSBOM(ctx, c, cfg, envRef, "")
}

// EnvironmentSBOM renders the components live in an environment into Argo parameters. When sbomNameFilter is non-empty, only that SBOM's components are rendered.
func EnvironmentSBOM(ctx context.Context, c SBOMFetcher, cfg render.Config, envRef, sbomNameFilter string) ([]render.Param, []render.Notice, error) {
	versions, err := FromEnvironmentSBOM(ctx, c, envRef, sbomNameFilter)
	if err != nil {
		return nil, nil, err
	}
	return render.Versions(cfg, versions...)
}
