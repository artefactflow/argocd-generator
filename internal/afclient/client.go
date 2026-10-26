// Package afclient is a small typed client for the ArtefactFlow API, scoped to the endpoints the generator needs: resolving an environment, listing its active deployments, and fetching an SBOM version document.
//
// Authentication is centralised in a single RoundTripper that is shared by every call, so credentials are applied (and redacted from errors) in exactly one place. Callers supply service-account client credentials, never a token: see New. The base URL is always supplied by the caller and never hard-coded, per the ArtefactFlow integration rules.
package afclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client talks to one ArtefactFlow API instance.
type Client struct {
	baseURL string
	http    *http.Client
	retry   retryPolicy
}

// retryPolicy bounds how the client rides out transient upstream failures. Only idempotent GETs are retried, and only on failures a retry could plausibly fix: connection errors, HTTP 429, and 5xx. Permanent failures (4xx other than 429) never retry. The point is resilience to blips, not masking outages: an exhausted retry still fails loudly so the caller keeps its last known-good set rather than pruning.
type retryPolicy struct {
	maxAttempts int           // total tries including the first; <1 is clamped to 1
	baseDelay   time.Duration // backoff before the 2nd attempt; doubles each round
	maxDelay    time.Duration // ceiling on any single backoff sleep
}

func defaultRetry() retryPolicy {
	return retryPolicy{maxAttempts: 3, baseDelay: 200 * time.Millisecond, maxDelay: 5 * time.Second}
}

// delay computes the backoff before the retry following attempt index (0-based: 0 is the wait before the 2nd attempt). A server-supplied Retry-After wins, capped at maxDelay so one slow API can't stall a whole reconcile. Otherwise it is exponential with full jitter in [d/2, d], so a fleet of controllers does not synchronise its retry storm against a recovering API.
func (p retryPolicy) delay(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return min(retryAfter, p.maxDelay)
	}
	if p.baseDelay <= 0 {
		return 0
	}
	d := p.baseDelay
	for i := 0; i < attempt && d < p.maxDelay; i++ {
		d *= 2
	}
	if d > p.maxDelay {
		d = p.maxDelay
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

// UserAgent identifies the tool and its version on every request, including the token exchange, so ArtefactFlow can tell which release a service account runs: that is how users of a vulnerable release are found and told. main sets it from the build version.
var UserAgent = "argocd-generator/dev"

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the underlying HTTP client. The bearer transport is layered on top of the provided client's transport.
func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

// WithRetry overrides the bounded-retry policy for transient upstream failures. maxAttempts is the total number of tries including the first; a value below 1 is clamped to 1, which disables retries. baseDelay is the backoff before the second attempt and doubles each round up to maxDelay.
func WithRetry(maxAttempts int, baseDelay, maxDelay time.Duration) Option {
	return func(c *Client) {
		if maxAttempts < 1 {
			maxAttempts = 1
		}
		c.retry = retryPolicy{maxAttempts: maxAttempts, baseDelay: baseDelay, maxDelay: maxDelay}
	}
}

// New builds a Client for baseURL that authenticates as the service account identified by clientID and clientSecret. Both are required.
//
// An already-minted bearer token is deliberately not accepted. Accepting one would make it easy to run the generator as a human user, which carries that person's full scope set and stops working when they leave. A plugin that reconciles for weeks would also be holding a token that expires long before it does. Requiring a service account makes least privilege the only option, and lets the client re-authenticate for as long as it runs.
//
// Credentials are never logged and are redacted from errors. Nothing is sent until the first API call, so New does not fail on bad credentials: the first request does.
func New(baseURL, clientID, clientSecret string, opts ...Option) (*Client, error) {
	if clientID == "" {
		return nil, fmt.Errorf("afclient: client id is required")
	}
	if clientSecret == "" {
		return nil, fmt.Errorf("afclient: client secret is required")
	}
	c, err := newClient(baseURL, opts...)
	if err != nil {
		return nil, err
	}
	base := c.http.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	// The minter is an unauthenticated client sharing this one's base URL, retry policy, and underlying transport. Minting through the authenticated transport would recurse: the transport would ask the token source for a token, which would issue the very request being authorised. It gets its own *http.Client (a copy, not the caller's) because WithHTTPClient would otherwise hand both clients the same struct and wrapping c's transport below would silently wrap the minter's too.
	minterHTTP := *c.http
	minterHTTP.Transport = base
	minter := &Client{baseURL: c.baseURL, http: &minterHTTP, retry: c.retry}

	c.http.Transport = &authTransport{tokens: newTokenSource(minter, clientID, clientSecret), base: base}
	return c, nil
}

// newClient builds an unauthenticated client. Only the token endpoint uses one directly: every other call goes through New and carries a bearer token.
func newClient(baseURL string, opts ...Option) (*Client, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("afclient: base URL is required")
	}
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
		retry:   defaultRetry(),
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// authTransport injects the Authorization header on every request, minting and refreshing the access token as needed. Keeping it as a RoundTripper means auth is defined once and reused for all endpoints, including the tolerant SBOM-version fetch.
type authTransport struct {
	tokens *tokenSource
	base   http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.tokens.Token(req.Context())
	if err != nil {
		return nil, err
	}
	resp, err := t.roundTripWith(req, token)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}

	// The token was accepted when minted and rejected now: it expired sooner than stated, or was revoked. Discard it and try once with a fresh one. Retrying only on 401, and only once, keeps a genuinely invalid credential from looping, and the second 401 is returned as-is.
	//
	// Safe to replay: every authenticated call is an idempotent GET, and a request with a body is left alone because its reader is already drained.
	if req.Body != nil && req.GetBody == nil {
		return resp, nil
	}
	resp.Body.Close()
	t.tokens.Invalidate()
	token, err = t.tokens.Token(req.Context())
	if err != nil {
		return nil, err
	}
	return t.roundTripWith(req, token)
}

func (t *authTransport) roundTripWith(req *http.Request, token string) (*http.Response, error) {
	// Clone before mutating: RoundTrippers must not modify the caller's request.
	r := req.Clone(req.Context())
	if req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		r.Body = body
	}
	r.Header.Set("Authorization", "Bearer "+token)
	return t.base.RoundTrip(r)
}

// getJSON performs a GET against path (relative to the base URL) and decodes a 200 body into dst. Non-200 responses become errors that name the status and a bounded snippet of the body, never the token.
func (c *Client) getJSON(ctx context.Context, path string, query url.Values, dst any) error {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	body, err := c.getRaw(ctx, u)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// getRaw performs a GET and returns the raw 200 body.
func (c *Client) getRaw(ctx context.Context, fullURL string) ([]byte, error) {
	return c.doRaw(ctx, http.MethodGet, fullURL, nil)
}

// doRaw performs a request and returns the raw 200 body, mapping non-200 statuses to descriptive errors. Transient failures (connection errors, HTTP 429, and 5xx) are retried with exponential backoff and jitter, bounded by the client's retry policy; permanent failures (4xx other than 429) return immediately. The point is resilience to blips, not masking outages: an exhausted retry still fails loudly so the caller keeps its last known-good set rather than pruning.
//
// reqBody is held as bytes rather than a reader so each attempt can build a fresh request. Only two calls use this: an idempotent GET, and the POST that mints a token. Replaying that one mints another token and has no other effect, so it is equally safe to retry.
func (c *Client) doRaw(ctx context.Context, method, fullURL string, reqBody []byte) ([]byte, error) {
	var (
		lastErr        error
		lastRetryAfter time.Duration
	)
	for attempt := 0; attempt < c.retry.maxAttempts; attempt++ {
		if attempt > 0 {
			if err := waitBackoff(ctx, c.retry.delay(attempt-1, lastRetryAfter)); err != nil {
				return nil, err
			}
		}
		body, retryable, retryAfter, err := c.doOnce(ctx, method, fullURL, reqBody)
		if err == nil {
			return body, nil
		}
		lastErr, lastRetryAfter = err, retryAfter
		if !retryable {
			return nil, err
		}
	}
	return nil, lastErr
}

// doOnce performs a single attempt. It reports whether the failure is worth retrying and any server-requested Retry-After delay.
func (c *Client) doOnce(ctx context.Context, method, fullURL string, reqBody []byte) (body []byte, retryable bool, retryAfter time.Duration, err error) {
	var payload io.Reader
	if reqBody != nil {
		payload = bytes.NewReader(reqBody)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, payload)
	if err != nil {
		return nil, false, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// A cancelled or timed-out context is deliberate, so never retry it.
		if ctx.Err() != nil {
			return nil, false, 0, err
		}
		// Connection refused/reset, DNS failure, etc: transient, worth a retry.
		return nil, true, 0, err
	}
	defer resp.Body.Close()
	// SBOM version documents can be large; cap generously to avoid truncating a legitimate response (a truncated body would fail JSON parsing downstream).
	body, _ = io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode == http.StatusOK {
		return body, false, 0, nil
	}
	statusErr := &StatusError{Status: resp.StatusCode, Snippet: snippet(body)}
	if isRetryableStatus(resp.StatusCode) {
		return nil, true, parseRetryAfter(resp.Header.Get("Retry-After")), statusErr
	}
	return nil, false, 0, statusErr
}

// isRetryableStatus reports whether an HTTP status is a transient upstream failure worth retrying: rate limiting (429) or any server-side 5xx.
func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// parseRetryAfter reads the delta-seconds form of a Retry-After header. The HTTP-date form is ignored (returns 0), falling back to normal backoff.
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

// waitBackoff sleeps for d, returning early with the context error if ctx is cancelled first so a retry loop never outlives its deadline.
func waitBackoff(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// StatusError is a non-200 response from the ArtefactFlow API.
type StatusError struct {
	Status  int
	Snippet string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("artefactflow api returned HTTP %d: %s", e.Status, e.Snippet)
}

func snippet(b []byte) string {
	const max = 512
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
