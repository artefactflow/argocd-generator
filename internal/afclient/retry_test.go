package afclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newRetryClient builds a client with instant (zero-delay) backoff so retry behaviour can be asserted without slowing the test.
func newRetryClient(t *testing.T, url string, attempts int) *Client {
	t.Helper()
	c, err := New(url, testClientID, testClientSecret, WithRetry(attempts, 0, 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestGetRaw_RetriesTransientThenSucceeds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(withTokenEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, `{"metadata":{"has_more":false},"environments":[
			{"id":"01991041-f06c-767d-acc4-fb0a9f11280a","slug":"production"}]}`)
	})))
	defer srv.Close()

	c := newRetryClient(t, srv.URL, 3)
	id, err := c.ResolveEnvironmentID(context.Background(), "production")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id != "01991041-f06c-767d-acc4-fb0a9f11280a" {
		t.Fatalf("got %q", id)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("want 3 attempts (2 transient + success), got %d", got)
	}
}

func TestGetRaw_ExhaustsRetriesAndReturnsStatusError(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(withTokenEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "boom", http.StatusBadGateway)
	})))
	defer srv.Close()

	c := newRetryClient(t, srv.URL, 3)
	_, err := c.GetSBOMVersion(context.Background(), "x", "1.0.0")
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusBadGateway {
		t.Fatalf("want wrapped StatusError 502, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("want 3 attempts, got %d", got)
	}
}

func TestGetRaw_DoesNotRetryPermanentStatus(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(withTokenEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "forbidden", http.StatusForbidden)
	})))
	defer srv.Close()

	c := newRetryClient(t, srv.URL, 5)
	if _, err := c.GetSBOMVersion(context.Background(), "x", "1.0.0"); err == nil {
		t.Fatal("expected error on 403")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("a permanent 403 must not be retried, got %d attempts", got)
	}
}

// flakyRoundTripper fails the first failFirst calls with a connection error, then delegates to base. It stands in for a flapping network path.
type flakyRoundTripper struct {
	mu        sync.Mutex
	calls     int
	failFirst int
	base      http.RoundTripper
}

func (f *flakyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Authentication is not what this test is exercising: let the token mint through untouched so calls counts only the API call under test.
	if req.URL.Path == "/v1/auth/token" {
		return f.base.RoundTrip(req)
	}
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.mu.Unlock()
	if n <= f.failFirst {
		return nil, &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	}
	return f.base.RoundTrip(req)
}

func TestGetRaw_RetriesConnectionErrors(t *testing.T) {
	srv := mockAPI(t)
	defer srv.Close()

	flaky := &flakyRoundTripper{failFirst: 2, base: http.DefaultTransport}
	c, err := New(srv.URL, testClientID, testClientSecret,
		WithHTTPClient(&http.Client{Transport: flaky}), WithRetry(3, 0, 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	id, err := c.ResolveEnvironmentID(context.Background(), "production")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id != "01991041-f06c-767d-acc4-fb0a9f11280a" {
		t.Fatalf("got %q", id)
	}
	if flaky.calls != 3 {
		t.Fatalf("want 3 attempts (2 connection errors + success), got %d", flaky.calls)
	}
}

func TestGetRaw_ContextCancelStopsRetries(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(withTokenEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	})))
	defer srv.Close()

	// A long backoff guarantees the cancel lands during the wait, not mid-request.
	c, err := New(srv.URL, testClientID, testClientSecret, WithRetry(5, time.Hour, time.Hour))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err = c.GetSBOMVersion(ctx, "x", "1.0.0")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("want 1 attempt before the cancel aborts backoff, got %d", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"0", 0},
		{"-2", 0},
		{"abc", 0},
		{"5", 5 * time.Second},
		{"  3 ", 3 * time.Second},
		{"Wed, 21 Oct 2026 07:28:00 GMT", 0}, // HTTP-date form is not honored
	}
	for _, tc := range cases {
		if got := parseRetryAfter(tc.in); got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestRetryPolicyDelay(t *testing.T) {
	p := retryPolicy{maxAttempts: 5, baseDelay: 100 * time.Millisecond, maxDelay: 800 * time.Millisecond}

	// Jittered exponential backoff never exceeds maxDelay or goes negative.
	for attempt := 0; attempt < 6; attempt++ {
		d := p.delay(attempt, 0)
		if d < 0 || d > p.maxDelay {
			t.Errorf("attempt %d: delay %v out of [0, %v]", attempt, d, p.maxDelay)
		}
	}
	// Retry-After is honored, but capped at maxDelay.
	if d := p.delay(0, 2*time.Second); d != p.maxDelay {
		t.Errorf("retry-after over cap: got %v, want %v", d, p.maxDelay)
	}
	if d := p.delay(0, 300*time.Millisecond); d != 300*time.Millisecond {
		t.Errorf("retry-after under cap: got %v, want 300ms", d)
	}
}

func TestWithRetry_ClampsToAtLeastOneAttempt(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(withTokenEndpoint(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	})))
	defer srv.Close()

	c, err := New(srv.URL, testClientID, testClientSecret, WithRetry(0, 0, 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.GetSBOMVersion(context.Background(), "x", "1.0.0"); err == nil {
		t.Fatal("expected error")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("maxAttempts<1 must still make exactly 1 attempt, got %d", got)
	}
}
