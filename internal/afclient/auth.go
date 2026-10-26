package afclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// tokenRequest is the client-credentials body. grant_type is accepted but ignored by the API (the client-credentials grant is assumed), so it is not sent.
type tokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// tokenResponse is the minted access token. The expiry field is `expire_in` on the wire, and it is a count of seconds rather than a timestamp.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpireIn    int    `json:"expire_in"`
	TokenType   string `json:"token_type"`
}

// Authenticate exchanges service-account client credentials for a short-lived access token, which is the same bearer token the rest of the API expects. It returns the token and the number of seconds it remains valid.
//
// The token endpoint lives on the same origin as everything else, so baseURL is the one the caller already has. The credentials appear only in the request body: they are never logged, and the error paths below deliberately quote the API's own message rather than anything derived from the request.
func Authenticate(ctx context.Context, baseURL, clientID, clientSecret string, opts ...Option) (string, time.Duration, error) {
	c, err := newClient(baseURL, opts...)
	if err != nil {
		return "", 0, err
	}
	return c.mintToken(ctx, clientID, clientSecret)
}

// mintToken performs the token exchange against this client's base URL. The client must be unauthenticated: minting through the authenticated transport would recurse.
func (c *Client) mintToken(ctx context.Context, clientID, clientSecret string) (string, time.Duration, error) {
	payload, err := json.Marshal(tokenRequest{ClientID: clientID, ClientSecret: clientSecret})
	if err != nil {
		return "", 0, fmt.Errorf("authenticate: %w", err)
	}

	body, err := c.doRaw(ctx, http.MethodPost, c.baseURL+"/v1/auth/token", payload)
	if err != nil {
		// This is the one call that puts a secret on the wire, and a failed response can quote the request back: a validation error listing the offending field, or a proxy echoing the body. Scrub before the error can reach a log line or an ApplicationSet controller event.
		return "", 0, fmt.Errorf("authenticate service account %s: %w", clientID, redact(err, clientSecret))
	}

	var resp tokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", 0, fmt.Errorf("authenticate service account %s: decode token response: %w", clientID, err)
	}
	if resp.AccessToken == "" {
		return "", 0, fmt.Errorf("authenticate service account %s: response contained no access_token", clientID)
	}
	return resp.AccessToken, time.Duration(resp.ExpireIn) * time.Second, nil
}

// redact replaces every occurrence of secret in err's message with a placeholder. The typed error is flattened in the process, which no caller depends on, and an unreadable error is a smaller problem than a leaked credential.
//
// Very short values are left alone: they are not real secrets (the API requires at least 8 characters), and replacing them would corrupt unrelated text.
func redact(err error, secret string) error {
	if err == nil || len(secret) < 8 {
		return err
	}
	msg := err.Error()
	if !strings.Contains(msg, secret) {
		return err
	}
	return errors.New(strings.ReplaceAll(msg, secret, "«client-secret redacted»"))
}

// tokenSource mints access tokens on demand and caches the current one until it is close to expiring.
//
// Caching is what makes the difference between the CLI and the plugin server. A CLI run mints once and exits, but `serve` runs for weeks and answers a reconcile every couple of minutes: minting per request would turn every generated Application into two API calls instead of one, and re-authenticating on a schedule the API controls is the only way a long-lived process survives its token expiring mid-reconcile.
type tokenSource struct {
	minter       *Client // unauthenticated; used only for /v1/auth/token
	clientID     string
	clientSecret string
	now          func() time.Time // injectable for tests

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// expirySkew is how long before the stated expiry a token is treated as already expired. It covers clock drift between us and the API plus the flight time of a request that is authorised on departure and validated on arrival.
const expirySkew = 60 * time.Second

// defaultTokenTTL is used when the API states no expiry. Short enough that a mistaken assumption is corrected quickly, long enough not to re-authenticate every reconcile.
const defaultTokenTTL = 5 * time.Minute

func newTokenSource(minter *Client, clientID, clientSecret string) *tokenSource {
	return &tokenSource{minter: minter, clientID: clientID, clientSecret: clientSecret, now: time.Now}
}

// Token returns a valid access token, minting a new one if the cached token is missing or near expiry. Concurrent callers (the ApplicationSet controller can have several reconciles in flight) block on the mutex rather than each minting their own, so a token refresh costs one request no matter how many requests are waiting on it.
func (s *tokenSource) Token(ctx context.Context) (string, error) {
	return s.token_(ctx, false)
}

// Invalidate discards the cached token so the next Token call mints a fresh one. Used when the API rejects a token we believed was still valid.
func (s *tokenSource) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = ""
	s.expiresAt = time.Time{}
}

func (s *tokenSource) token_(ctx context.Context, force bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !force && s.token != "" && s.now().Before(s.expiresAt) {
		return s.token, nil
	}

	token, ttl, err := s.minter.mintToken(ctx, s.clientID, s.clientSecret)
	if err != nil {
		return "", err
	}
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	// A token whose whole life is shorter than the skew is still usable right now; keeping a non-zero window avoids re-minting on literally every call.
	usable := ttl - expirySkew
	if usable <= 0 {
		usable = ttl / 2
	}
	s.token = token
	s.expiresAt = s.now().Add(usable)
	return token, nil
}
