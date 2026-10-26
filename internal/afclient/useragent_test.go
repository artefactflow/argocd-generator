package afclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The User-Agent is how ArtefactFlow tells which release of a tool a service account runs, so it has to be on every request, the token exchange included.
func TestUserAgentIsSentOnEveryRequest(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	previous := UserAgent
	UserAgent = "tool-under-test/1.2.3"
	defer func() { UserAgent = previous }()

	c, err := newClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.doRaw(context.Background(), http.MethodPost, srv.URL+"/v1/auth/token", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if got != "tool-under-test/1.2.3" {
		t.Fatalf("User-Agent = %q, want %q", got, "tool-under-test/1.2.3")
	}
}
