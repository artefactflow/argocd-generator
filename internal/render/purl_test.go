package render

import "testing"

func TestParsePURL(t *testing.T) {
	cases := []struct {
		purl     string
		wantType string
		wantPath string
	}{
		{"pkg:docker/acme/checkout-service", "docker", "acme/checkout-service"},
		{"pkg:docker/acme/checkout-service@1.5.0", "docker", "acme/checkout-service"},
		{"pkg:docker/nginx", "docker", "nginx"},
		{"pkg:oci/acme/api@sha256:abc?repository_url=ghcr.io", "oci", "acme/api"},
		{"pkg:npm/%40acme/admin-portal", "npm", "@acme/admin-portal"},
		{"pkg:golang/github.com/acme/mod@v1.2.3", "golang", "github.com/acme/mod"},
		{"", "", ""},
		{"not-a-purl", "", ""},
	}
	for _, c := range cases {
		gotType, gotPath := parsePURL(c.purl)
		if gotType != c.wantType || gotPath != c.wantPath {
			t.Errorf("parsePURL(%q) = (%q, %q), want (%q, %q)", c.purl, gotType, gotPath, c.wantType, c.wantPath)
		}
	}
}

func TestImageRepositoryFromPURL(t *testing.T) {
	cases := map[string]string{
		"pkg:docker/acme/checkout-service": "acme/checkout-service",
		"pkg:oci/acme/api":                 "acme/api",
		"pkg:npm/%40acme/admin-portal":     "", // non-container: no image repository
		"pkg:golang/github.com/acme/mod":   "",
		"":                                 "",
	}
	for purl, want := range cases {
		if got := imageRepositoryFromPURL(purl); got != want {
			t.Errorf("imageRepositoryFromPURL(%q) = %q, want %q", purl, got, want)
		}
	}
}
