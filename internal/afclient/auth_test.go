package afclient

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tokenServer serves the token endpoint, counting mints and handing out a distinct token each time so a caller can tell a cached token from a refreshed one. ttl is the advertised expire_in.
func tokenServer(t *testing.T, ttl int, mints *int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(mints, 1)
		writeJSON(w, fmt.Sprintf(`{"access_token":"token-%d","expire_in":%d,"token_type":"Bearer"}`, n, ttl))
	})
	return httptest.NewServer(mux)
}

func TestAuthenticate_ReturnsTokenAndTTL(t *testing.T) {
	var mints int32
	srv := tokenServer(t, 3600, &mints)
	defer srv.Close()

	token, ttl, err := Authenticate(context.Background(), srv.URL, testClientID, testClientSecret)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if token != "token-1" {
		t.Errorf("token = %q", token)
	}
	if ttl != time.Hour {
		t.Errorf("ttl = %v, want 1h", ttl)
	}
}

func TestAuthenticate_RejectsBadCredentials(t *testing.T) {
	srv := httptest.NewServer(withTokenEndpoint(t, http.NotFoundHandler()))
	defer srv.Close()

	_, _, err := Authenticate(context.Background(), srv.URL, testClientID, "wrong-secret-value")
	if err == nil {
		t.Fatal("expected an error for invalid credentials")
	}
	if !strings.Contains(err.Error(), testClientID) {
		t.Errorf("error should name the service account, got %v", err)
	}
}

// A failed token request is the one response that can quote the request back: a validation error naming the offending field, or a proxy echoing the body. The secret must not survive into an error that reaches a log line.
func TestAuthenticate_RedactsSecretFromErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"invalid client_secret: `+testClientSecret+`"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	_, _, err := Authenticate(context.Background(), srv.URL, testClientID, testClientSecret)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), testClientSecret) {
		t.Fatalf("client secret leaked into error: %v", err)
	}
	if !strings.Contains(err.Error(), "redacted") {
		t.Errorf("want a redaction marker, got %v", err)
	}
}

func TestTokenSource_CachesToken(t *testing.T) {
	var mints int32
	srv := tokenServer(t, 3600, &mints)
	defer srv.Close()

	minter, err := newClient(srv.URL)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	src := newTokenSource(minter, testClientID, testClientSecret)

	for i := 0; i < 5; i++ {
		token, err := src.Token(context.Background())
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		if token != "token-1" {
			t.Fatalf("call %d got %q, want the cached token-1", i, token)
		}
	}
	if got := atomic.LoadInt32(&mints); got != 1 {
		t.Errorf("want 1 mint for 5 calls, got %d", got)
	}
}

func TestTokenSource_RefreshesBeforeExpiry(t *testing.T) {
	var mints int32
	// A 10-minute token: with the 60s skew it is treated as expired after 9 minutes.
	srv := tokenServer(t, 600, &mints)
	defer srv.Close()

	minter, err := newClient(srv.URL)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	src := newTokenSource(minter, testClientID, testClientSecret)

	now := time.Now()
	src.now = func() time.Time { return now }

	if token, _ := src.Token(context.Background()); token != "token-1" {
		t.Fatalf("first token = %q", token)
	}

	// Eight minutes in: still inside the usable window.
	now = now.Add(8 * time.Minute)
	if token, _ := src.Token(context.Background()); token != "token-1" {
		t.Errorf("token should still be cached at 8m, got %q", token)
	}

	// Past the skew-adjusted expiry, but before the token itself expires. The point of the skew is that the refresh happens while the old token would still work.
	now = now.Add(2 * time.Minute)
	if token, _ := src.Token(context.Background()); token != "token-2" {
		t.Errorf("token should have refreshed at 10m, got %q", token)
	}
	if got := atomic.LoadInt32(&mints); got != 2 {
		t.Errorf("want 2 mints, got %d", got)
	}
}

// A token whose entire life is shorter than the skew must still be usable, and must not send the source into a mint-per-call loop.
func TestTokenSource_HandlesTinyTTL(t *testing.T) {
	var mints int32
	srv := tokenServer(t, 10, &mints)
	defer srv.Close()

	minter, _ := newClient(srv.URL)
	src := newTokenSource(minter, testClientID, testClientSecret)
	now := time.Now()
	src.now = func() time.Time { return now }

	if _, err := src.Token(context.Background()); err != nil {
		t.Fatalf("token: %v", err)
	}
	now = now.Add(time.Second)
	if _, err := src.Token(context.Background()); err != nil {
		t.Fatalf("token: %v", err)
	}
	if got := atomic.LoadInt32(&mints); got != 1 {
		t.Errorf("a 10s token should still be reused a second later, got %d mints", got)
	}
}

// The controller can have several reconciles in flight. A refresh must cost one mint no matter how many callers are waiting on it.
func TestTokenSource_ConcurrentCallersMintOnce(t *testing.T) {
	var mints int32
	srv := tokenServer(t, 3600, &mints)
	defer srv.Close()

	minter, _ := newClient(srv.URL)
	src := newTokenSource(minter, testClientID, testClientSecret)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := src.Token(context.Background()); err != nil {
				t.Errorf("token: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&mints); got != 1 {
		t.Errorf("want 1 mint across 20 concurrent callers, got %d", got)
	}
}

// A token can be revoked, or expire earlier than advertised. The transport should notice the 401, discard the cached token, and retry once with a fresh one rather than failing a reconcile.
func TestAuthTransport_RefreshesOnUnauthorized(t *testing.T) {
	var mints, apiCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&mints, 1)
		writeJSON(w, fmt.Sprintf(`{"access_token":"token-%d","expire_in":3600,"token_type":"Bearer"}`, n))
	})
	mux.HandleFunc("/v1/environments", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&apiCalls, 1)
		// The first token is treated as revoked; the second is accepted.
		if r.Header.Get("Authorization") == "Bearer token-1" {
			http.Error(w, `{"message":"token expired"}`, http.StatusUnauthorized)
			return
		}
		writeJSON(w, `{"metadata":{"has_more":false},"environments":[{"id":"01991041-f06c-767d-acc4-fb0a9f11280a","slug":"production"}]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := New(srv.URL, testClientID, testClientSecret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	id, err := c.ResolveEnvironmentID(context.Background(), "production")
	if err != nil {
		t.Fatalf("resolve should have recovered from the 401: %v", err)
	}
	if id != "01991041-f06c-767d-acc4-fb0a9f11280a" {
		t.Errorf("id = %q", id)
	}
	if got := atomic.LoadInt32(&mints); got != 2 {
		t.Errorf("want 2 mints (initial + refresh), got %d", got)
	}
	if got := atomic.LoadInt32(&apiCalls); got != 2 {
		t.Errorf("want 2 API calls (401 + retry), got %d", got)
	}
}

// A credential that is genuinely invalid must fail rather than loop: exactly one refresh is attempted, and the second 401 is returned.
func TestAuthTransport_DoesNotLoopOnPersistentUnauthorized(t *testing.T) {
	var apiCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"access_token":"token","expire_in":3600,"token_type":"Bearer"}`)
	})
	mux.HandleFunc("/v1/environments", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&apiCalls, 1)
		http.Error(w, `{"message":"forbidden"}`, http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := New(srv.URL, testClientID, testClientSecret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.ResolveEnvironmentID(context.Background(), "production"); err == nil {
		t.Fatal("expected the second 401 to surface")
	}
	if got := atomic.LoadInt32(&apiCalls); got != 2 {
		t.Errorf("want exactly 2 API calls (no retry loop), got %d", got)
	}
}

// One token should serve a whole reconcile, not one per request.
func TestClient_MintsOnceAcrossCalls(t *testing.T) {
	var mints int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&mints, 1)
		writeJSON(w, `{"access_token":"test-token","expire_in":3600,"token_type":"Bearer"}`)
	})
	mux.HandleFunc("/v1/environments", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, `{"metadata":{"has_more":false},"environments":[{"id":"01991041-f06c-767d-acc4-fb0a9f11280a","slug":"production"}]}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := New(srv.URL, testClientID, testClientSecret)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := c.ResolveEnvironmentID(context.Background(), "production"); err != nil {
			t.Fatalf("resolve: %v", err)
		}
	}
	if got := atomic.LoadInt32(&mints); got != 1 {
		t.Errorf("want 1 mint across 3 calls, got %d", got)
	}
}

func TestRedact(t *testing.T) {
	err := fmt.Errorf("boom: %s", testClientSecret)
	if got := redact(err, testClientSecret).Error(); strings.Contains(got, testClientSecret) {
		t.Errorf("secret survived redaction: %s", got)
	}
	// Short values are not real secrets and replacing them would corrupt unrelated text.
	short := fmt.Errorf("status 404")
	if got := redact(short, "404").Error(); got != "status 404" {
		t.Errorf("short value should be left alone, got %q", got)
	}
}
