// Package server implements the Argo CD ApplicationSet plugin generator HTTP contract. The ApplicationSet controller POSTs to /api/v1/getparams.execute on each reconcile; this server authenticates that request, resolves what is live in the requested environment via the ArtefactFlow API, and returns one parameter object per component under output.parameters.
//
// Two independent tokens are in play. The pre-shared plugin token authenticates the controller to this server (checked here). The upstream service-account credentials are held by the injected client and never seen by the controller.
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/artefactflow/argocd-generator/internal/generate"
	"github.com/artefactflow/argocd-generator/internal/render"
)

// Config configures the plugin server.
type Config struct {
	// PluginToken is the pre-shared token the ApplicationSet controller must present. Required.
	PluginToken string
	// Render controls component selection and defaulting.
	Render render.Config
	// AllowEmpty permits returning an empty parameter list. It is false by default: an empty 200 makes the controller prune every generated Application, so a wrong environment or a transient upstream blip would tear down every app. When false, an empty result is refused with a non-2xx status so the controller keeps its last known-good set.
	AllowEmpty bool
	// Logger is used for request diagnostics. Defaults to slog.Default().
	Logger *slog.Logger
}

// Server serves the plugin generator endpoint.
type Server struct {
	cfg    Config
	client generate.SBOMFetcher
	log    *slog.Logger

	// lastNotices remembers, per ApplicationSet, the exclusion report of the previous reconcile, so an unchanged set is summarised rather than restated in full every couple of minutes for weeks. See logNotices.
	noticesMu   sync.Mutex
	lastNotices map[string]string
}

// New builds a Server. client is the ArtefactFlow API client used to resolve environments and fetch SBOM versions.
func New(cfg Config, client generate.SBOMFetcher) (*Server, error) {
	if cfg.PluginToken == "" {
		return nil, errors.New("server: plugin token is required")
	}
	if client == nil {
		return nil, errors.New("server: client is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{cfg: cfg, client: client, log: cfg.Logger, lastNotices: map[string]string{}}, nil
}

// logNotices records why components were left out of the returned set.
//
// This is the audit trail behind the never-drop rule: Argo CD deletes any Application missing from the response, so an operator has to be able to answer "why is this app gone" from the logs alone. The controller reconciles every couple of minutes and the answer is almost always identical, so the full detail is logged whenever it changes and summarised while it holds steady, so an unchanged report stays greppable without writing the same eight lines forever.
func (s *Server) logNotices(applicationSet, environment string, notices []render.Notice) {
	excluded := 0
	fingerprint := make([]string, 0, len(notices))
	for _, n := range notices {
		if n.Excluded {
			excluded++
		}
		fingerprint = append(fingerprint, n.String())
	}
	key := applicationSet + "\x00" + environment
	joined := strings.Join(fingerprint, "\n")

	s.noticesMu.Lock()
	changed := s.lastNotices[key] != joined
	s.lastNotices[key] = joined
	s.noticesMu.Unlock()

	if !changed {
		s.log.Debug("component exclusions unchanged",
			"applicationSet", applicationSet, "environment", environment, "excluded", excluded)
		return
	}
	for _, n := range notices {
		s.log.Info("component not rendered as an Application",
			"applicationSet", applicationSet, "environment", environment,
			"component", n.Name, "purl", n.PURL, "reason", n.Reason, "detail", n.Detail, "excluded", n.Excluded)
	}
	s.log.Info("component exclusion report",
		"applicationSet", applicationSet, "environment", environment, "excluded", excluded, "notices", len(notices))
}

// Handler returns the HTTP handler with the plugin and health routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/getparams.execute", s.handleExecute)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return s.recoverPanic(mux)
}

// recoverPanic turns a handler panic into a 500 instead of a dropped connection, and never lets one bad request take the long-running server down.
func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("recovered from panic", "path", r.URL.Path, "panic", rec)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ListenAndServe starts the server on addr with sane header/idle timeouts and shuts down gracefully when ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("plugin server listening", "addr", addr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		s.log.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}

// execRequest is the getparams.execute request body. input.parameters carries the values declared on the ApplicationSet's plugin generator.
type execRequest struct {
	ApplicationSetName string `json:"applicationSetName"`
	Input              struct {
		Parameters map[string]any `json:"parameters"`
	} `json:"input"`
}

type execResponse struct {
	Output struct {
		Parameters []render.Param `json:"parameters"`
	} `json:"output"`
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var req execRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	environment := stringParam(req.Input.Parameters, "environment")
	sbomName := stringParam(req.Input.Parameters, "sbomName")
	if environment == "" {
		http.Error(w, "input.parameters.environment is required", http.StatusBadRequest)
		return
	}

	params, notices, err := generate.EnvironmentSBOM(r.Context(), s.client, s.cfg.Render, environment, sbomName)
	if err != nil {
		// Never answer 200 on failure: an error (or empty) 200 tells the controller every generated Application is gone and it prunes them. A non-2xx makes the reconcile error and keep the last known-good set.
		s.log.Error("getparams.execute failed",
			"applicationSet", req.ApplicationSetName, "environment", environment, "sbom", sbomName, "error", err)
		http.Error(w, "resolve failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	if len(notices) > 0 {
		s.logNotices(req.ApplicationSetName, environment, notices)
	}

	if len(params) == 0 && !s.cfg.AllowEmpty {
		s.log.Warn("refusing to return an empty parameter set (would prune all Applications); set AllowEmpty to permit",
			"applicationSet", req.ApplicationSetName, "environment", environment, "sbom", sbomName)
		http.Error(w, "no components resolved; refusing to prune (enable allow-empty to permit)", http.StatusUnprocessableEntity)
		return
	}

	var resp execResponse
	resp.Output.Parameters = params
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.log.Error("failed to encode response", "error", err)
	}
}

// authorized reports whether the request carries the pre-shared plugin token. The comparison is constant-time.
func (s *Server) authorized(r *http.Request) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.PluginToken)) == 1
}

// stringParam reads a string-valued plugin parameter, tolerating absence and non-string values.
func stringParam(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}
