// Command argocd-gen renders Argo CD ApplicationSet parameters from ArtefactFlow SBOM versions. It supports three inputs, all producing the same parameter list: a local SBOM version file (offline), a single SBOM name+version from the API, or every SBOM live in an environment. The ApplicationSet plugin server is layered on top of this same core.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/artefactflow/argocd-generator/internal/afclient"
	"github.com/artefactflow/argocd-generator/internal/generate"
	"github.com/artefactflow/argocd-generator/internal/render"
	"github.com/artefactflow/argocd-generator/internal/sbom"
	"github.com/artefactflow/argocd-generator/internal/server"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	afclient.UserAgent = "argocd-generator/" + version
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "generate":
		if err := runGenerate(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "version", "--version", "-v":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":4355", "listen address for the plugin generator")
	apiURL := fs.String("api-url", os.Getenv("ARTEFACTFLOW_API_URL"), "ArtefactFlow API base URL (env ARTEFACTFLOW_API_URL)")
	clientID := fs.String("client-id", os.Getenv("ARTEFACTFLOW_CLIENT_ID"), "service-account client id (env ARTEFACTFLOW_CLIENT_ID); the secret comes from ARTEFACTFLOW_CLIENT_SECRET")
	allowEmpty := fs.Bool("allow-empty", false, "permit an empty parameter set (prunes all Applications); off by default")
	defaultNamespace := fs.String("default-namespace", os.Getenv("ARGOCD_DEFAULT_NAMESPACE"), "destination namespace for components that set no argocd_namespace and whose group is not a usable namespace; unset makes that an error")
	componentTypes := fs.String("component-types", os.Getenv("ARGOCD_COMPONENT_TYPES"), "comma-separated CycloneDX component types to render (default \"application,container\"); \"all\" renders every type")
	noFold := fs.Bool("no-fold", false, "render a component claimed by another (see --claim-property) as its own Application instead of folding it into the claimer")
	claimProperty := fs.String("claim-property", os.Getenv("ARGOCD_CLAIM_PROPERTY"), "property by which a component names what it deploys (default \"deploys-image\")")
	deployUnconfigured := fs.Bool("deploy-unconfigured", false, "render components that carry no argocd_* property at all, instead of treating them as inventory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	client, err := apiClient(*apiURL, *clientID)
	if err != nil {
		return err
	}
	pluginToken := os.Getenv("ARGOCD_PLUGIN_TOKEN")
	if pluginToken == "" {
		return fmt.Errorf("ARGOCD_PLUGIN_TOKEN is required")
	}

	renderCfg := render.Defaults()
	renderCfg.DefaultNamespace = *defaultNamespace
	renderCfg.DisableFold = *noFold
	renderCfg.DeployUnconfigured = *deployUnconfigured
	if *claimProperty != "" {
		renderCfg.ClaimProperty = *claimProperty
	}
	if *componentTypes != "" {
		renderCfg.ComponentTypes = parseComponentTypes(*componentTypes)
	}

	srv, err := server.New(server.Config{
		PluginToken: pluginToken,
		Render:      renderCfg,
		AllowEmpty:  *allowEmpty,
		Logger:      logger,
	}, client)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger.Info("starting argocd-generator", "version", version)
	return srv.ListenAndServe(ctx, *addr)
}

func runGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	file := fs.String("sbom-file", "", "path to a local SBOM version JSON file (offline mode)")
	environment := fs.String("environment", "", "environment slug or id: render every SBOM live in it")
	sbomName := fs.String("sbom", "", "SBOM name (with --version): render a single SBOM version")
	version := fs.String("version", "", "SBOM version value (with --sbom)")
	apiURL := fs.String("api-url", os.Getenv("ARTEFACTFLOW_API_URL"), "ArtefactFlow API base URL (env ARTEFACTFLOW_API_URL)")
	clientID := fs.String("client-id", os.Getenv("ARTEFACTFLOW_CLIENT_ID"), "service-account client id (env ARTEFACTFLOW_CLIENT_ID); the secret comes from ARTEFACTFLOW_CLIENT_SECRET")
	defaultNamespace := fs.String("default-namespace", os.Getenv("ARGOCD_DEFAULT_NAMESPACE"), "destination namespace for components that set no argocd_namespace and whose group is not a usable namespace; unset makes that an error")
	componentTypes := fs.String("component-types", "", "comma-separated CycloneDX component types to render (default \"application,container\"); \"all\" renders every type")
	noFold := fs.Bool("no-fold", false, "render a component claimed by another (see --claim-property) as its own Application instead of folding it into the claimer")
	claimProperty := fs.String("claim-property", "", "property by which a component names what it deploys (default \"deploys-image\")")
	deployUnconfigured := fs.Bool("deploy-unconfigured", false, "render components that carry no argocd_* property at all, instead of treating them as inventory")
	quiet := fs.Bool("quiet", false, "do not print the component exclusion report to stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := render.Defaults()
	cfg.DefaultNamespace = *defaultNamespace
	cfg.DisableFold = *noFold
	cfg.DeployUnconfigured = *deployUnconfigured
	if *claimProperty != "" {
		cfg.ClaimProperty = *claimProperty
	}
	if *componentTypes != "" {
		cfg.ComponentTypes = parseComponentTypes(*componentTypes)
	}

	params, notices, err := resolveParams(context.Background(), cfg, *file, *environment, *sbomName, *version, *apiURL, *clientID)
	if err != nil {
		return err
	}
	if !*quiet {
		printNotices(os.Stderr, notices)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(params)
}

// parseComponentTypes reads the --component-types value. "all" becomes an empty list, which the renderer treats as "no type filter". Spelling it out is friendlier than requiring an operator to pass an empty string.
func parseComponentTypes(s string) []string {
	if strings.EqualFold(strings.TrimSpace(s), "all") {
		return []string{}
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// printNotices writes the exclusion report to stderr, leaving stdout as clean JSON for a pipeline.
//
// It prints even when nothing was excluded is false, because silence would be indistinguishable from "nothing was dropped", and the whole point of the report is that a component missing from the output is a component Argo CD will delete.
func printNotices(w io.Writer, notices []render.Notice) {
	if len(notices) == 0 {
		return
	}
	excluded := 0
	for _, n := range notices {
		if n.Excluded {
			excluded++
		}
	}
	switch advisories := len(notices) - excluded; {
	case excluded == 0:
		fmt.Fprintf(w, "all components rendered; %d advisory notice(s):\n", advisories)
	case advisories == 0:
		fmt.Fprintf(w, "%d component(s) not rendered as Applications:\n", excluded)
	default:
		fmt.Fprintf(w, "%d component(s) not rendered as Applications, %d advisory notice(s):\n", excluded, advisories)
	}
	for _, n := range notices {
		marker := "note"
		if n.Excluded {
			marker = "skip"
		}
		fmt.Fprintf(w, "  [%s] %s\n", marker, n)
	}
}

func resolveParams(ctx context.Context, cfg render.Config, file, environment, sbomName, version, apiURL, clientID string) ([]render.Param, []render.Notice, error) {
	switch {
	case file != "":
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, nil, err
		}
		v, err := sbom.Parse(data)
		if err != nil {
			return nil, nil, err
		}
		return render.Versions(cfg, v)

	case environment != "":
		c, err := apiClient(apiURL, clientID)
		if err != nil {
			return nil, nil, err
		}
		return generate.Environment(ctx, c, cfg, environment)

	case sbomName != "" && version != "":
		c, err := apiClient(apiURL, clientID)
		if err != nil {
			return nil, nil, err
		}
		v, err := generate.FromSBOM(ctx, c, sbomName, version)
		if err != nil {
			return nil, nil, err
		}
		return render.Versions(cfg, v)

	default:
		return nil, nil, fmt.Errorf("provide one of: --sbom-file, --environment, or --sbom with --version")
	}
}

// apiClient builds the ArtefactFlow client from the service-account credentials in the environment.
//
// The secret is read from the environment only, never a flag: a flag value is visible in `ps` output and lands in shell history. The client id may be a flag because it is an identifier, not a credential.
func apiClient(apiURL, clientID string) (*afclient.Client, error) {
	// Lower-cased before the check, as the other ArtefactFlow integrations do, so a UUID copied in upper case still works: the API itself accepts only the lowercase spelling.
	clientID = strings.ToLower(clientID)
	if apiURL == "" {
		return nil, fmt.Errorf("--api-url (or ARTEFACTFLOW_API_URL) is required")
	}
	clientSecret := os.Getenv("ARTEFACTFLOW_CLIENT_SECRET")
	switch {
	case clientID == "" && clientSecret == "":
		return nil, fmt.Errorf("service-account credentials are required: set --client-id (or ARTEFACTFLOW_CLIENT_ID) and ARTEFACTFLOW_CLIENT_SECRET")
	case clientID == "":
		return nil, fmt.Errorf("ARTEFACTFLOW_CLIENT_SECRET was set without --client-id (or ARTEFACTFLOW_CLIENT_ID)")
	case clientSecret == "":
		return nil, fmt.Errorf("--client-id was set without ARTEFACTFLOW_CLIENT_SECRET")
	// The client id is the service account's own id, a UUID. Checking it locally catches the common mistake of pasting the account name, which the API would answer with an indistinguishable "invalid credentials".
	case !afclient.IsResourceID(clientID):
		return nil, fmt.Errorf("--client-id must be the service account's id, a UUID such as 0198e2c3-9a21-7b8e-90f5-6c1d4e2a83b0, got %q", clientID)
	}
	return afclient.New(apiURL, clientID, clientSecret)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  argocd-gen generate --sbom-file <path>")
	fmt.Fprintln(os.Stderr, "  argocd-gen generate --environment <slug|id>       [--api-url URL] [--client-id ID]")
	fmt.Fprintln(os.Stderr, "  argocd-gen generate --sbom <name> --version <ver> [--api-url URL] [--client-id ID]")
	fmt.Fprintln(os.Stderr, "  argocd-gen serve [--addr :4355] [--api-url URL] [--client-id ID] [--allow-empty]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  argocd-gen version")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  component selection (both generate and serve):")
	fmt.Fprintln(os.Stderr, "    --default-namespace NS   namespace for components that set none")
	fmt.Fprintln(os.Stderr, "    --component-types LIST   CycloneDX types to render (default application,container; \"all\" for every type)")
	fmt.Fprintln(os.Stderr, "    --claim-property NAME    property naming what a component deploys (default deploys-image)")
	fmt.Fprintln(os.Stderr, "    --no-fold                render claimed components as their own Applications")
	fmt.Fprintln(os.Stderr, "    --deploy-unconfigured    render components that carry no argocd_* property")
	fmt.Fprintln(os.Stderr, "  generate also accepts --quiet to suppress the exclusion report on stderr")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "env: ARTEFACTFLOW_API_URL, ARTEFACTFLOW_CLIENT_ID, ARTEFACTFLOW_CLIENT_SECRET,")
	fmt.Fprintln(os.Stderr, "     ARGOCD_DEFAULT_NAMESPACE, ARGOCD_COMPONENT_TYPES, ARGOCD_CLAIM_PROPERTY,")
	fmt.Fprintln(os.Stderr, "     ARGOCD_PLUGIN_TOKEN (serve)")
}
