package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/artefactflow/argocd-generator/internal/afclient"
	"github.com/artefactflow/argocd-generator/internal/render"
	"github.com/artefactflow/argocd-generator/internal/sbom"
)

type fakeFetcher struct {
	deps   []afclient.Deployment
	byName map[string]*sbom.Version
	err    error
}

func (f *fakeFetcher) ResolveEnvironmentID(_ context.Context, ref string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return "env-" + ref, nil
}
func (f *fakeFetcher) ActiveDeployments(_ context.Context, _ string) ([]afclient.Deployment, error) {
	return f.deps, nil
}
func (f *fakeFetcher) GetSBOMVersion(_ context.Context, name, _ string) (*sbom.Version, error) {
	v, ok := f.byName[name]
	if !ok {
		return nil, errors.New("not found: " + name)
	}
	return v, nil
}

func newServer(t *testing.T, f *fakeFetcher, allowEmpty bool) *Server {
	t.Helper()
	s, err := New(Config{PluginToken: "shared", Render: render.Defaults(), AllowEmpty: allowEmpty}, f)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func execRequestBody(env, sbomName string) string {
	p := map[string]any{"environment": env}
	if sbomName != "" {
		p["sbomName"] = sbomName
	}
	b, _ := json.Marshal(map[string]any{"applicationSetName": "as", "input": map[string]any{"parameters": p}})
	return string(b)
}

func do(t *testing.T, s *Server, method, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/api/v1/getparams.execute", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func oneSBOM() *fakeFetcher {
	return &fakeFetcher{
		deps: []afclient.Deployment{{SbomName: "bom", VersionValue: "1.0.0"}},
		byName: map[string]*sbom.Version{
			"bom": {BOMFormat: "CycloneDX", Components: []sbom.Component{
				{Name: "svc", Type: "application", ArtefactID: "a", Version: "1.0.0", Group: "apps",
					Properties: []sbom.Property{{Name: "argocd_path", Value: "apps/svc"}}},
			}},
		},
	}
}

func TestExecute_HappyPath(t *testing.T) {
	s := newServer(t, oneSBOM(), false)
	rr := do(t, s, http.MethodPost, "shared", execRequestBody("production", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp execResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Output.Parameters) != 1 {
		t.Fatalf("want 1 param, got %d", len(resp.Output.Parameters))
	}
	if resp.Output.Parameters[0]["rawName"] != "svc" {
		t.Errorf("unexpected param: %+v", resp.Output.Parameters[0])
	}
}

func TestExecute_ForbiddenOnWrongToken(t *testing.T) {
	s := newServer(t, oneSBOM(), false)
	if rr := do(t, s, http.MethodPost, "nope", execRequestBody("production", "")); rr.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rr.Code)
	}
	if rr := do(t, s, http.MethodPost, "", execRequestBody("production", "")); rr.Code != http.StatusForbidden {
		t.Fatalf("want 403 for missing token, got %d", rr.Code)
	}
}

func TestExecute_MethodNotAllowed(t *testing.T) {
	s := newServer(t, oneSBOM(), false)
	if rr := do(t, s, http.MethodGet, "shared", ""); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}

func TestExecute_MissingEnvironment(t *testing.T) {
	s := newServer(t, oneSBOM(), false)
	if rr := do(t, s, http.MethodPost, "shared", `{"input":{"parameters":{}}}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rr.Code)
	}
}

func TestExecute_RefusesEmpty(t *testing.T) {
	f := &fakeFetcher{deps: nil, byName: map[string]*sbom.Version{}} // no deployments
	s := newServer(t, f, false)
	rr := do(t, s, http.MethodPost, "shared", execRequestBody("production", ""))
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422 refusing to prune, got %d (body %s)", rr.Code, rr.Body.String())
	}
}

func TestExecute_AllowEmpty(t *testing.T) {
	f := &fakeFetcher{deps: nil, byName: map[string]*sbom.Version{}}
	s := newServer(t, f, true)
	rr := do(t, s, http.MethodPost, "shared", execRequestBody("production", ""))
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200 with allow-empty, got %d", rr.Code)
	}
}

func TestExecute_UpstreamFailureIsNon2xx(t *testing.T) {
	f := oneSBOM()
	f.err = errors.New("artefactflow api down")
	s := newServer(t, f, false)
	rr := do(t, s, http.MethodPost, "shared", execRequestBody("production", ""))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("want 502 on upstream failure (keep last known-good), got %d", rr.Code)
	}
}

func TestExecute_SBOMFilter(t *testing.T) {
	f := &fakeFetcher{
		deps: []afclient.Deployment{
			{SbomName: "keep", VersionValue: "1.0.0"},
			{SbomName: "drop", VersionValue: "1.0.0"},
		},
		byName: map[string]*sbom.Version{
			"keep": {BOMFormat: "CycloneDX", Components: []sbom.Component{{Name: "k", Type: "application", ArtefactID: "k", Version: "1", Group: "apps", Properties: []sbom.Property{{Name: "argocd_path", Value: "apps/k"}}}}},
			"drop": {BOMFormat: "CycloneDX", Components: []sbom.Component{{Name: "d", Type: "application", ArtefactID: "d", Version: "1", Group: "apps", Properties: []sbom.Property{{Name: "argocd_path", Value: "apps/d"}}}}},
		},
	}
	s := newServer(t, f, false)
	rr := do(t, s, http.MethodPost, "shared", execRequestBody("production", "keep"))
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d", rr.Code)
	}
	var resp execResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Output.Parameters) != 1 || resp.Output.Parameters[0]["rawName"] != "k" {
		t.Fatalf("filter failed: %+v", resp.Output.Parameters)
	}
}

// panicFetcher panics inside a request to exercise the recovery middleware.
type panicFetcher struct{}

func (panicFetcher) ResolveEnvironmentID(context.Context, string) (string, error) { return "env", nil }
func (panicFetcher) ActiveDeployments(context.Context, string) ([]afclient.Deployment, error) {
	panic("boom")
}
func (panicFetcher) GetSBOMVersion(context.Context, string, string) (*sbom.Version, error) {
	return nil, nil
}

func TestExecute_RecoversFromPanic(t *testing.T) {
	s, err := New(Config{PluginToken: "shared", Render: render.Defaults()}, panicFetcher{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rr := do(t, s, http.MethodPost, "shared", execRequestBody("production", ""))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 from panic recovery, got %d", rr.Code)
	}
}

func TestHealthz(t *testing.T) {
	s := newServer(t, oneSBOM(), false)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rr.Code)
	}
}
