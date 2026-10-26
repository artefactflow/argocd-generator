package afclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// testClientID and testClientSecret are the credentials every test authenticates with. The secret is long enough to exercise the redaction path, which ignores anything under 8 characters.
const (
	testClientID     = "0199cffa-e497-7ef0-b9c5-7babd3c0e9fc"
	testClientSecret = "afsa_test_client_secret_value"
)

// withTokenEndpoint mounts the client-credentials endpoint in front of h, so a handler under test only ever sees the API calls it cares about. Every client now authenticates before its first request; without this, the mint call would land on the handler and be counted as an attempt.
func withTokenEndpoint(t *testing.T, h http.Handler) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("token endpoint called with %s, want POST", r.Method)
		}
		var req tokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode token request: %v", err)
		}
		if req.ClientID != testClientID || req.ClientSecret != testClientSecret {
			http.Error(w, `{"message":"invalid credentials"}`, http.StatusUnauthorized)
			return
		}
		writeJSON(w, `{"access_token":"test-token","expire_in":3600,"token_type":"Bearer"}`)
	})
	mux.Handle("/", h)
	return mux
}

// mockAPI is a minimal stand-in for the ArtefactFlow API covering the three endpoints the generator uses, plus the token endpoint every client hits first.
func mockAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/environments", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("missing/wrong bearer on %s: %q", r.URL.Path, got)
		}
		writeJSON(w, `{"metadata":{"has_more":false},"environments":[
			{"id":"01991041-f06c-767d-acc4-fb0a9f11280a","name":"Production","slug":"production"},
			{"id":"0199390a-f23a-7077-91fc-44c5c2c76863","name":"Staging","slug":"staging"}]}`)
	})

	mux.HandleFunc("/v1/environments/01991041-f06c-767d-acc4-fb0a9f11280a/deployments/active", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"metadata":{},"deployments":[
			{"sbom_id":"0199fbed-dec2-742a-a5e0-9019cbeef288","sbom_name":"acme-platform-bom","version_value":"2.4.0","environment_slug":"production","status":"active"}]}`)
	})

	mux.HandleFunc("/v1/sboms/acme-platform-bom/versions/2.4.0", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"bomFormat":"CycloneDX","specVersion":"1.7","version":"2.4.0","components":[
			{"artefact_id":"0199cffa-e497-7ef0-b9c5-7babd3c0e9fc","bom-ref":"ref-1","type":"application","name":"checkout-service","group":"com.acme.payments","version":"1.5.0","purl":"pkg:docker/acme/checkout-service","source":"https://git.example.com/checkout",
			 "properties":[{"name":"argocd_repo_url","value":"https://git.example.com/deploy"},{"name":"argocd_path","value":"charts/svc"},{"name":"argocd_namespace","value":"payments"}]}]}`)
	})

	return httptest.NewServer(withTokenEndpoint(t, mux))
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func newTestClient(t *testing.T, url string) *Client {
	t.Helper()
	c, err := New(url, testClientID, testClientSecret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestResolveEnvironmentID_BySlug(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	id, err := c.ResolveEnvironmentID(context.Background(), "production")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id != "01991041-f06c-767d-acc4-fb0a9f11280a" {
		t.Errorf("got %q", id)
	}
}

func TestResolveEnvironmentID_AcceptsResourceID(t *testing.T) {
	c := newTestClient(t, "http://unused.invalid")
	id, err := c.ResolveEnvironmentID(context.Background(), "01991041-f06c-767d-acc4-fb0a9f11280a")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id != "01991041-f06c-767d-acc4-fb0a9f11280a" {
		t.Errorf("id should pass through, got %q", id)
	}
}

// The API accepts only the canonical spelling of an id, so anything else must not pass through as one: a legacy 24-hex id, or a UUID in another spelling, is looked up as a slug instead.
func TestIsResourceID(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"0198e2c3-9a21-7b8e-90f5-6c1d4e2a83b0", true},
		{"507f191e810c19729de860ed", false},
		{"0198e2c39a217b8e90f56c1d4e2a83b0", false},
		{"0198E2C3-9A21-7B8E-90F5-6C1D4E2A83B0", false},
		{"urn:uuid:0198e2c3-9a21-7b8e-90f5-6c1d4e2a83b0", false},
		{"production", false},
		{"", false},
	} {
		if got := IsResourceID(tc.in); got != tc.want {
			t.Errorf("IsResourceID(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestResolveEnvironmentID_NotFound(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	if _, err := c.ResolveEnvironmentID(context.Background(), "does-not-exist"); err == nil {
		t.Fatal("expected error for unknown slug")
	}
}

func TestActiveDeploymentsAndVersion(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	deps, err := c.ActiveDeployments(context.Background(), "01991041-f06c-767d-acc4-fb0a9f11280a")
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if len(deps) != 1 || deps[0].SbomName != "acme-platform-bom" {
		t.Fatalf("unexpected deployments: %+v", deps)
	}

	v, err := c.GetSBOMVersion(context.Background(), deps[0].SbomName, deps[0].VersionValue)
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if len(v.Components) != 1 || v.Components[0].Name != "checkout-service" {
		t.Fatalf("unexpected components: %+v", v.Components)
	}
}

func TestGetSBOMVersion_StatusError(t *testing.T) {
	srv := httptest.NewServer(withTokenEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})))
	defer srv.Close()
	c := newTestClient(t, srv.URL)

	_, err := c.GetSBOMVersion(context.Background(), "x", "1.0.0")
	if err == nil {
		t.Fatal("expected error on 403")
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusForbidden {
		t.Errorf("want wrapped StatusError 403, got %v", err)
	}
}

func TestNew_Validation(t *testing.T) {
	if _, err := New("", testClientID, testClientSecret); err == nil {
		t.Error("expected error for empty base URL")
	}
	if _, err := New("http://x", "", testClientSecret); err == nil {
		t.Error("expected error for empty client id")
	}
	if _, err := New("http://x", testClientID, ""); err == nil {
		t.Error("expected error for empty client secret")
	}
}
