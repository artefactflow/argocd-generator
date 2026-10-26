package generate

import (
	"context"
	"errors"
	"testing"

	"github.com/artefactflow/argocd-generator/internal/afclient"
	"github.com/artefactflow/argocd-generator/internal/render"
	"github.com/artefactflow/argocd-generator/internal/sbom"
)

// fakeFetcher drives the orchestration without a live API.
type fakeFetcher struct {
	envID   string
	deps    []afclient.Deployment
	byName  map[string]*sbom.Version
	failFor string // sbom name that should error on fetch
}

func (f *fakeFetcher) ResolveEnvironmentID(_ context.Context, _ string) (string, error) {
	return f.envID, nil
}
func (f *fakeFetcher) ActiveDeployments(_ context.Context, _ string) ([]afclient.Deployment, error) {
	return f.deps, nil
}
func (f *fakeFetcher) GetSBOMVersion(_ context.Context, name, _ string) (*sbom.Version, error) {
	if name == f.failFor {
		return nil, errors.New("boom")
	}
	return f.byName[name], nil
}

func comp(name string) sbom.Component {
	// Group doubles as the destination namespace, so it must be a valid one: an unusable namespace is a render error.
	return sbom.Component{
		Name: name, Type: "application", ArtefactID: name, Version: "1.0.0", Group: "apps",
		// A component with no argocd_* property at all is inventory rather than a deployment, so give these one: the subject here is how SBOMs are flattened, not which components deploy.
		Properties: []sbom.Property{{Name: "argocd_path", Value: "apps/" + name}},
	}
}

func TestEnvironment_FlattensAllSBOMs(t *testing.T) {
	f := &fakeFetcher{
		deps: []afclient.Deployment{
			{SbomName: "a", VersionValue: "1.0.0"},
			{SbomName: "b", VersionValue: "2.0.0"},
		},
		byName: map[string]*sbom.Version{
			"a": {BOMFormat: "CycloneDX", Components: []sbom.Component{comp("alpha")}},
			"b": {BOMFormat: "CycloneDX", Components: []sbom.Component{comp("bravo"), comp("charlie")}},
		},
	}
	params, _, err := Environment(context.Background(), f, render.Defaults(), "production")
	if err != nil {
		t.Fatalf("Environment: %v", err)
	}
	if len(params) != 3 {
		t.Fatalf("want 3 params across both SBOMs, got %d", len(params))
	}
}

func TestEnvironment_FailsLoudOnPartial(t *testing.T) {
	f := &fakeFetcher{
		deps: []afclient.Deployment{
			{SbomName: "a", VersionValue: "1.0.0"},
			{SbomName: "b", VersionValue: "2.0.0"},
		},
		byName:  map[string]*sbom.Version{"a": {BOMFormat: "CycloneDX", Components: []sbom.Component{comp("alpha")}}},
		failFor: "b",
	}
	if _, _, err := Environment(context.Background(), f, render.Defaults(), "production"); err == nil {
		t.Fatal("expected failure when one member SBOM cannot be fetched (never a partial set)")
	}
}

func TestEnvironment_MissingSbomNameFails(t *testing.T) {
	f := &fakeFetcher{
		deps: []afclient.Deployment{{SbomID: "xyz", VersionValue: "1.0.0"}}, // no SbomName
	}
	if _, _, err := Environment(context.Background(), f, render.Defaults(), "production"); err == nil {
		t.Fatal("expected failure when a deployment has no sbom_name")
	}
}

func TestEnvironment_SkipsNonActive(t *testing.T) {
	f := &fakeFetcher{
		deps: []afclient.Deployment{
			{SbomName: "live", VersionValue: "1.0.0", Status: "active"},
			{SbomName: "old", VersionValue: "0.9.0", Status: "superseded"},
		},
		byName: map[string]*sbom.Version{
			"live": {BOMFormat: "CycloneDX", Components: []sbom.Component{comp("live-svc")}},
			// "old" intentionally absent: if it were fetched, GetSBOMVersion would error.
		},
	}
	params, _, err := Environment(context.Background(), f, render.Defaults(), "production")
	if err != nil {
		t.Fatalf("Environment: %v", err)
	}
	if len(params) != 1 || params[0]["rawName"] != "live-svc" {
		t.Fatalf("should render only the active deployment, got %+v", params)
	}
}
