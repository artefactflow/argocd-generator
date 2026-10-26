package render

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/artefactflow/argocd-generator/internal/sbom"
)

var update = flag.Bool("update", false, "update golden files")

// TestVersions_Golden renders the repository's example SBOM version and compares the parameter list against a golden file. Run with -update to regenerate.
func TestVersions_Golden(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "example.sbomversion.json"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	v, err := sbom.Parse(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	got, notices, err := Versions(Defaults(), v)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	t.Logf("%d notice(s) from the example SBOM", len(notices))
	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	gotJSON = append(gotJSON, '\n')

	golden := filepath.Join("testdata", "expected_params.json")
	if *update {
		if err := os.WriteFile(golden, gotJSON, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if string(gotJSON) != string(want) {
		t.Errorf("rendered params differ from golden.\n--- got ---\n%s\n--- want ---\n%s", gotJSON, want)
	}
}

// TestVersions_TypeFilter confirms only selected component types are rendered.
func TestVersions_TypeFilter(t *testing.T) {
	v := &sbom.Version{
		BOMFormat: "CycloneDX",
		Components: []sbom.Component{
			{Name: "app", Type: "application", ArtefactID: "a", Group: "apps"},
			{Name: "lib", Type: "library", ArtefactID: "b"},
		},
	}
	got, _, err := Versions(deployAll(), v)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 param (application only), got %d", len(got))
	}
	if got[0]["rawName"] != "app" {
		t.Errorf("want app, got %v", got[0]["rawName"])
	}
}

// TestVersions_NameStaysLabelSafe confirms a very long component name yields an Application name that, even with a template prefix like "sbom-", stays within the 63-character instance-label limit.
func TestVersions_NameStaysLabelSafe(t *testing.T) {
	longName := "this-is-an-extremely-long-component-name-that-exceeds-any-reasonable-limit-by-a-lot"
	v := &sbom.Version{
		BOMFormat: "CycloneDX",
		Components: []sbom.Component{{
			Name: longName, Type: "application", ArtefactID: "x", Version: "1.0.0", Group: "apps",
		}},
	}
	name := mustRender(t, deployAll(), v)[0]["name"].(string)
	if len(name) > 53 {
		t.Errorf("name %q is %d chars; must be <= 53 so 'sbom-'+name <= 63", name, len(name))
	}
	if len("sbom-"+name) > 63 {
		t.Errorf("prefixed name exceeds the 63-char label limit: %q", "sbom-"+name)
	}
}

// TestVersions_NonContainerPURL confirms a non-OCI component gets an empty image repository (never a misleading one) and its purl_type is surfaced.
func TestVersions_NonContainerPURL(t *testing.T) {
	v := &sbom.Version{
		BOMFormat: "CycloneDX",
		Components: []sbom.Component{{
			Name: "portal", Type: "application", ArtefactID: "x", Version: "3.0.0",
			Group: "apps", PURL: "pkg:npm/%40acme/admin-portal",
		}},
	}
	p := mustRender(t, deployAll(), v)[0]
	if p["image_repository"] != "" {
		t.Errorf("non-container image_repository should be empty, got %v", p["image_repository"])
	}
	if p["purl_type"] != "npm" {
		t.Errorf("purl_type should be npm, got %v", p["purl_type"])
	}
}

// TestVersions_Defaults confirms a component with no argocd_* properties falls back to source-as-repo, group-as-namespace, and the standard defaults. The group here is a flat name, which is the only case where the namespace fallback applies. See TestVersions_RejectsUnusableNamespace.
func TestVersions_Defaults(t *testing.T) {
	v := &sbom.Version{
		BOMFormat: "CycloneDX",
		Components: []sbom.Component{{
			Name: "bare", Type: "application", ArtefactID: "x",
			Group: "web", Source: "https://git.example.com/web/bare",
			Version: "3.0.0",
		}},
	}
	p := mustRender(t, deployAll(), v)[0]
	if p["argocd_repo_url"] != "https://git.example.com/web/bare" {
		t.Errorf("repo_url should default to source, got %v", p["argocd_repo_url"])
	}
	if p["argocd_namespace"] != "web" {
		t.Errorf("namespace should default to group, got %v", p["argocd_namespace"])
	}
	if p["argocd_project"] != "default" {
		t.Errorf("project should default to 'default', got %v", p["argocd_project"])
	}
	if p["argocd_target_revision"] != "HEAD" {
		t.Errorf("target_revision should default to HEAD, got %v", p["argocd_target_revision"])
	}
	if vf, ok := p["argocd_value_files"].([]string); !ok || len(vf) != 0 {
		t.Errorf("value_files should be empty slice, got %v", p["argocd_value_files"])
	}
}

// TestParseHelmParameters covers the shapes an operator will actually type into a property value, including the ones that must be rejected rather than emitted as a parameter Argo CD would refuse.
func TestParseHelmParameters(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []HelmParameter
	}{
		{"empty", "", nil},
		{"single", "replicaCount=3", []HelmParameter{{"replicaCount", "3"}}},
		{
			"dotted paths are the common case",
			"resources.limits.cpu=500m,ingress.enabled=true",
			[]HelmParameter{{"resources.limits.cpu", "500m"}, {"ingress.enabled", "true"}},
		},
		// Only the first `=` splits, so a value may contain more of them.
		{"value containing =", "annotations=a=b", []HelmParameter{{"annotations", "a=b"}}},
		{"surrounding space is trimmed", " a = 1 , b = 2 ", []HelmParameter{{"a", "1"}, {"b", "2"}}},
		{"empty value is allowed", "disabled=", []HelmParameter{{"disabled", ""}}},
		// A bare word is not a parameter, and an empty name would be rejected by Argo CD.
		{"entry without = is dropped", "replicaCount", nil},
		{"empty name is dropped", "=3", nil},
		{"blank entries are dropped", "a=1,,b=2", []HelmParameter{{"a", "1"}, {"b", "2"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseHelmParameters(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("entry %d: got %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// Ordering is load-bearing: Helm applies later parameters last, so the image parameters the template emits first can be deliberately overridden by a component, and never the other way round by accident.
func TestVersions_HelmParametersPreserveOrder(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{{
		Type: "application", Name: "svc", Version: "1.0.0", Group: "apps",
		Properties: []sbom.Property{{Name: "argocd_helm_parameters", Value: "z=1,a=2,m=3"}},
	}}}
	params, ok := mustRender(t, deployAll(), v)[0]["argocd_helm_parameters"].([]HelmParameter)
	if !ok {
		t.Fatal("argocd_helm_parameters should be a []HelmParameter")
	}
	for i, want := range []string{"z", "a", "m"} {
		if params[i].Name != want {
			t.Errorf("position %d: got %q, want %q", i, params[i].Name, want)
		}
	}
}

// An unset property must still emit an empty list, so a template can range over it under missingkey=error.
func TestVersions_HelmParametersDefaultEmpty(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{{Type: "application", Name: "svc", Group: "apps"}}}
	got := mustRender(t, deployAll(), v)[0]["argocd_helm_parameters"]
	if params, ok := got.([]HelmParameter); !ok || len(params) != 0 {
		t.Errorf("want empty []HelmParameter, got %#v", got)
	}
}

// deployAll is Defaults() with the inventory rule relaxed. Tests whose subject is defaulting, naming or deduplication build bare components with no argocd_* properties, which the shipped defaults now treat as inventory; opting in keeps those tests about the thing they are testing. The rule itself is covered by TestVersions_SkipsUnconfiguredComponents.
func deployAll() Config {
	cfg := Defaults()
	cfg.DeployUnconfigured = true
	return cfg
}

// mustRender renders and fails the test on error, for cases whose subject is the rendered output rather than the error path.
func mustRender(t *testing.T, cfg Config, versions ...*sbom.Version) []Param {
	t.Helper()
	params, _, err := Versions(cfg, versions...)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return params
}

// A component whose group is reverse-DNS has no usable namespace. Rewriting it to `com-acme-web` or falling back to `default` would both deploy successfully into a namespace nobody chose (CreateNamespace=true means Argo CD would create it), so this must fail instead.
func TestVersions_RejectsUnusableNamespace(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{{
		Type: "application", Name: "admin-portal", Group: "com.acme.web", Version: "3.0.0",
	}}}
	_, _, err := Versions(deployAll(), v)
	if err == nil {
		t.Fatal("a reverse-DNS group is not a namespace; expected an error")
	}
	for _, want := range []string{"admin-portal", "com.acme.web", "argocd_namespace"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should name %q so an operator can act on it, got: %v", want, err)
		}
	}
}

// A flat group is a perfectly good namespace, and using it saves setting a property on every artefact.
func TestVersions_AcceptsFlatGroupAsNamespace(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{{
		Type: "application", Name: "svc", Group: "payments", Version: "1.0.0",
	}}}
	if got := mustRender(t, deployAll(), v)[0]["argocd_namespace"]; got != "payments" {
		t.Errorf("got %q, want payments", got)
	}
}

// An explicit property is validated too, so a typo fails at generation time rather than at sync time.
func TestVersions_RejectsInvalidNamespaceProperty(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{{
		Type: "application", Name: "svc", Version: "1.0.0",
		Properties: []sbom.Property{{Name: "argocd_namespace", Value: "Payments Prod"}},
	}}}
	if _, _, err := Versions(deployAll(), v); err == nil {
		t.Fatal("expected an error for an invalid namespace property")
	}
}

// An operator who genuinely wants a blanket fallback can opt into one.
func TestVersions_DefaultNamespaceOptIn(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{{
		Type: "application", Name: "admin-portal", Group: "com.acme.web", Version: "3.0.0",
	}}}
	cfg := deployAll()
	cfg.DefaultNamespace = "sbom-apps"
	if got := mustRender(t, cfg, v)[0]["argocd_namespace"]; got != "sbom-apps" {
		t.Errorf("got %q, want sbom-apps", got)
	}

	// An explicit property still wins over the configured default.
	v.Components[0].Properties = []sbom.Property{{Name: "argocd_namespace", Value: "web"}}
	if got := mustRender(t, cfg, v)[0]["argocd_namespace"]; got != "web" {
		t.Errorf("property should win over the default, got %q", got)
	}
}

// A bad operator-supplied default is caught once, up front.
func TestVersions_RejectsInvalidDefaultNamespace(t *testing.T) {
	cfg := deployAll()
	cfg.DefaultNamespace = "Not A Namespace"
	if _, _, err := Versions(cfg, &sbom.Version{}); err == nil {
		t.Fatal("expected an error for an invalid configured default namespace")
	}
}

// A component shared by several SBOMs in one environment is one deployable thing. Emitting it once per SBOM would put duplicate metadata.name entries in a single ApplicationSet. This is observed on real data, where 17 components carried only 10 distinct identities.
func TestVersions_DeduplicatesSharedComponents(t *testing.T) {
	comp := sbom.Component{
		Type: "application", Name: "checkout-service", ArtefactID: "01993539-8065-7a77-97e8-4d7f62545446",
		Group: "payments", Version: "1.5.0",
	}
	a := &sbom.Version{Components: []sbom.Component{comp}}
	b := &sbom.Version{Components: []sbom.Component{comp}}
	c := &sbom.Version{Components: []sbom.Component{comp}}

	got := mustRender(t, deployAll(), a, b, c)
	if len(got) != 1 {
		t.Fatalf("a component in 3 SBOMs must render once, got %d", len(got))
	}
	if got[0]["rawName"] != "checkout-service" {
		t.Errorf("unexpected component: %v", got[0]["rawName"])
	}
}

// Two SBOMs claiming the same component at different versions is a real conflict: they would render one Application, and silently picking either deploys a version nobody asked for.
func TestVersions_RejectsConflictingDuplicates(t *testing.T) {
	base := sbom.Component{
		Type: "application", Name: "checkout-service", ArtefactID: "01993539-8065-7a77-97e8-4d7f62545446",
		Group: "payments",
	}
	older, newer := base, base
	older.Version = "1.5.0"
	newer.Version = "1.6.0"

	_, _, err := Versions(deployAll(),
		&sbom.Version{Components: []sbom.Component{older}},
		&sbom.Version{Components: []sbom.Component{newer}},
	)
	if err == nil {
		t.Fatal("two versions of one component in one environment must not be silently collapsed")
	}
	// The message has to say which values disagree, or the operator cannot act on it.
	for _, want := range []string{"checkout-service", "image_tag", "1.5.0", "1.6.0"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

// A Helm chart and the image it deploys are one workload described from two angles. Rendering both makes two Applications fight over the same resources, so the claimer is the deployment root and the claimed component folds into it.
func TestVersions_FoldsClaimedComponent(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{
		{
			Type: "application", Name: "checkout-service-chart", ArtefactID: "chart", Group: "payments",
			Version: "1.5.0", PURL: "pkg:helm/acme/checkout-service-chart",
			Properties: []sbom.Property{
				{Name: "deploys-image", Value: "pkg:docker/acme/checkout-service"},
				{Name: "argocd_chart", Value: "checkout-service"},
			},
		},
		{
			Type: "application", Name: "checkout-service", ArtefactID: "image", Group: "payments",
			Version: "1.5.0", PURL: "pkg:docker/acme/checkout-service",
			Properties: []sbom.Property{{Name: "argocd_path", Value: "apps/checkout-service"}},
		},
	}}

	got, notices, err := Versions(Defaults(), v)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("chart + image is one deployment; got %d Applications", len(got))
	}
	if got[0]["rawName"] != "checkout-service-chart" {
		t.Errorf("the claimer is the root, got %v", got[0]["rawName"])
	}
	// The fold is only safe because it is reported: an operator has to be able to explain a missing Application.
	var folded *Notice
	for i := range notices {
		if notices[i].Reason == ReasonFolded {
			folded = &notices[i]
		}
	}
	if folded == nil {
		t.Fatal("folding a component must produce a notice; a silent drop is what prunes production")
	}
	if folded.Name != "checkout-service" || !strings.Contains(folded.Detail, "checkout-service-chart") {
		t.Errorf("notice must name the component and its claimer, got %+v", *folded)
	}
}

// A chart's own purl is pkg:helm/..., so it carries no image, even though deploying it is how the image reaches the cluster. The claim supplies what the purl cannot, which is what removes the hand-copied image parameters from every chart.
func TestVersions_DerivesImageFromClaim(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{
		{
			Type: "application", Name: "chart", ArtefactID: "c", Group: "payments",
			Version: "9.9.9", PURL: "pkg:helm/acme/chart",
			Properties: []sbom.Property{
				{Name: "deploys-image", Value: "pkg:docker/acme/checkout-service"},
				{Name: "argocd_chart", Value: "checkout-service"},
			},
		},
		{
			Type: "application", Name: "image", ArtefactID: "i", Group: "payments",
			Version: "1.5.0", PURL: "pkg:docker/acme/checkout-service",
			Properties: []sbom.Property{{Name: "argocd_path", Value: "apps/checkout-service"}},
		},
	}}
	p := mustRender(t, Defaults(), v)[0]
	if p["image_repository"] != "acme/checkout-service" {
		t.Errorf("image_repository should come from the claimed component, got %v", p["image_repository"])
	}
	// The tag is the image's version, not the chart's - they differ here on purpose.
	if p["image_tag"] != "1.5.0" {
		t.Errorf("image_tag should be the image's version, got %v", p["image_tag"])
	}
	// Derivation deliberately does not touch argocd_helm_parameters: the shipped ApplicationSet template already renders image_repository/image_tag into Helm parameters, so writing them here too would emit each parameter twice.
	for _, hp := range p["argocd_helm_parameters"].([]HelmParameter) {
		if hp.Name == "image.repository" || hp.Name == "image.tag" {
			t.Errorf("derivation must not inject %q; the template renders it from image_repository", hp.Name)
		}
	}
}

// An operator who wrote image.tag by hand meant it. Derivation must leave the property alone; the template ranges over argocd_helm_parameters after the derived pair, so the explicit value is the one Argo CD applies.
func TestVersions_ExplicitImageParametersWin(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{
		{
			Type: "application", Name: "chart", ArtefactID: "c", Group: "payments",
			Version: "1.0.0", PURL: "pkg:helm/acme/chart",
			Properties: []sbom.Property{
				{Name: "deploys-image", Value: "pkg:docker/acme/checkout-service"},
				{Name: "argocd_helm_parameters", Value: "image.tag=pinned-by-hand"},
			},
		},
		{
			Type: "application", Name: "image", ArtefactID: "i", Group: "payments",
			Version: "1.5.0", PURL: "pkg:docker/acme/checkout-service",
			Properties: []sbom.Property{{Name: "argocd_path", Value: "apps/x"}},
		},
	}}
	got := mustRender(t, Defaults(), v)
	params := got[0]["argocd_helm_parameters"].([]HelmParameter)
	if len(params) != 1 || params[0].Name != "image.tag" || params[0].Value != "pinned-by-hand" {
		t.Errorf("the explicit parameter must survive untouched, got %+v", params)
	}
}

// Several charts deploying one image is normal - a shared sidecar, or a job chart beside a service chart. The image is not a root either way, and failing the whole environment over it would take down every Application in it.
func TestVersions_MultipleClaimersAreNotAnError(t *testing.T) {
	claimer := func(name string) sbom.Component {
		return sbom.Component{
			Type: "application", Name: name, ArtefactID: name, Group: "payments",
			Version: "1.0.0", PURL: "pkg:helm/acme/" + name,
			Properties: []sbom.Property{
				{Name: "deploys-image", Value: "pkg:docker/acme/shared"},
				{Name: "argocd_chart", Value: name},
			},
		}
	}
	v := &sbom.Version{Components: []sbom.Component{
		claimer("service-chart"), claimer("job-chart"),
		{
			Type: "application", Name: "shared", ArtefactID: "s", Group: "payments",
			Version: "2.0.0", PURL: "pkg:docker/acme/shared",
			Properties: []sbom.Property{{Name: "argocd_path", Value: "apps/shared"}},
		},
	}}
	got, notices, err := Versions(Defaults(), v)
	if err != nil {
		t.Fatalf("two charts deploying one image must not fail the environment: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("both claimers stay roots, got %d", len(got))
	}
	for _, n := range notices {
		if n.Reason == ReasonFolded {
			for _, want := range []string{"job-chart", "service-chart"} {
				if !strings.Contains(n.Detail, want) {
					t.Errorf("notice should name every claimer, missing %q in %q", want, n.Detail)
				}
			}
		}
	}
}

// A claim may name an image whose own SBOM is not deployed to this environment. The repository is still recoverable from the claim's purl, so the chart renders - only the tag is lost, and that is reported rather than fatal.
func TestVersions_ClaimTargetAbsentIsAdvisory(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{{
		Type: "application", Name: "chart", ArtefactID: "c", Group: "payments",
		Version: "1.0.0", PURL: "pkg:helm/acme/chart",
		Properties: []sbom.Property{
			{Name: "deploys-image", Value: "pkg:docker/acme/elsewhere"},
			{Name: "argocd_chart", Value: "chart"},
		},
	}}}
	got, notices, err := Versions(Defaults(), v)
	if err != nil {
		t.Fatalf("an absent claim target must not fail the environment: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("the claimer still deploys, got %d", len(got))
	}
	if got[0]["image_repository"] != "acme/elsewhere" {
		t.Errorf("repository is recoverable from the claim purl, got %v", got[0]["image_repository"])
	}
	if !hasReason(notices, ReasonClaimTargetAbsent) {
		t.Error("an unresolvable claim must be reported")
	}
}

// An environment holds npm packages, mobile apps and SDKs that are not Argo CD Applications under any definition. They are skipped - and reported, because the same silence would otherwise hide a chart whose properties someone forgot.
func TestVersions_SkipsUnconfiguredComponents(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{
		{
			Type: "application", Name: "admin-portal", ArtefactID: "p", Group: "com.acme.web",
			Version: "3.0.0", PURL: "pkg:npm/%40acme/admin-portal",
		},
		{
			Type: "application", Name: "checkout-service", ArtefactID: "c", Group: "payments",
			Version: "1.5.0", PURL: "pkg:docker/acme/checkout-service",
			Properties: []sbom.Property{{Name: "argocd_path", Value: "apps/checkout-service"}},
		},
	}}
	got, notices, err := Versions(Defaults(), v)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(got) != 1 || got[0]["rawName"] != "checkout-service" {
		t.Fatalf("only the configured component deploys, got %v", got)
	}
	if !hasReason(notices, ReasonNoDeploymentConfig) {
		t.Error("a skipped component must be reported")
	}
	// Before this rule, admin-portal reached the namespace check and failed the whole environment on a reverse-DNS group - a real environment could not be rendered at all.
	for _, n := range notices {
		if n.Reason == ReasonNoDeploymentConfig && n.Name != "admin-portal" {
			t.Errorf("unexpected component skipped: %q", n.Name)
		}
	}
}

// A type filter that drops components without saying so is the same failure as any other silent drop.
func TestVersions_TypeFilterIsReported(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{{
		Type: "library", Name: "acme-mobile-sdk", ArtefactID: "s", Group: "mobile",
		Version: "1.2.0", PURL: "pkg:maven/com.acme/acme-mobile-sdk",
	}}}
	got, notices, err := Versions(Defaults(), v)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a library is not an Application, got %d", len(got))
	}
	if !hasReason(notices, ReasonComponentType) {
		t.Error("a type-filtered component must be reported")
	}
}

// ArtefactFlow returns a bare {artefact_id, version} when it cannot resolve a component's artefact, and says so nowhere. Rendering that is impossible, and quietly filtering it out empties the environment: the one response that prunes every Application. It has to be an error.
func TestVersions_RejectsUnresolvedComponent(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{
		{ArtefactID: "0199fc2c-5475-7f59-a43d-d3b8cf06f967", Version: "1.5.0"},
	}}
	_, _, err := Versions(Defaults(), v)
	if err == nil {
		t.Fatal("an unresolved component must fail loudly, not vanish from the desired state")
	}
	for _, want := range []string{"0199fc2c-5475-7f59-a43d-d3b8cf06f967", "resolve"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

// The fold can be turned off, for an operator who really does deploy the chart and the image separately.
func TestVersions_FoldCanBeDisabled(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{
		{
			Type: "application", Name: "chart", ArtefactID: "c", Group: "payments",
			Version: "1.0.0", PURL: "pkg:helm/acme/chart",
			Properties: []sbom.Property{
				{Name: "deploys-image", Value: "pkg:docker/acme/img"},
				{Name: "argocd_chart", Value: "chart"},
			},
		},
		{
			Type: "application", Name: "img", ArtefactID: "i", Group: "payments",
			Version: "1.0.0", PURL: "pkg:docker/acme/img",
			Properties: []sbom.Property{{Name: "argocd_path", Value: "apps/img"}},
		},
	}}
	cfg := Defaults()
	cfg.DisableFold = true
	if got := mustRender(t, cfg, v); len(got) != 2 {
		t.Fatalf("with folding off both components render, got %d", len(got))
	}
}

// A claim that is not a package URL is a typo that would otherwise silently fold nothing.
func TestVersions_RejectsNonPURLClaim(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{{
		Type: "application", Name: "chart", ArtefactID: "c", Group: "payments",
		Version: "1.0.0", PURL: "pkg:helm/acme/chart",
		Properties: []sbom.Property{
			{Name: "deploys-image", Value: "acme/checkout-service"},
			{Name: "argocd_chart", Value: "chart"},
		},
	}}}
	if _, _, err := Versions(Defaults(), v); err == nil {
		t.Fatal("a claim that is not a purl must be rejected")
	}
}

func hasReason(notices []Notice, reason string) bool {
	for _, n := range notices {
		if n.Reason == reason {
			return true
		}
	}
	return false
}

// The exclusion report explains what was removed. The opposite failure is quieter and worse: a chart that should claim its image but does not removes nothing, so nothing is reported, and both components deploy: the double deployment the claim exists to prevent.
func TestVersions_WarnsOnUnclaimedPair(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{
		{
			Type: "application", Name: "checkout-service-chart", ArtefactID: "c", Group: "payments",
			Version: "1.5.0", PURL: "pkg:helm/acme/checkout-service-chart",
			Properties: []sbom.Property{{Name: "argocd_chart", Value: "checkout-service"}},
		},
		{
			Type: "container", Name: "checkout-service", ArtefactID: "i", Group: "payments",
			Version: "1.5.0", PURL: "pkg:docker/acme/checkout-service",
			Properties: []sbom.Property{{Name: "argocd_path", Value: "apps/checkout-service"}},
		},
	}}
	got, notices, err := Versions(Defaults(), v)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// The advisory does not change what is deployed - it explains why two Applications appear.
	if len(got) != 2 {
		t.Fatalf("without a claim both still render, got %d", len(got))
	}
	var n *Notice
	for i := range notices {
		if notices[i].Reason == ReasonUnclaimedPair {
			n = &notices[i]
		}
	}
	if n == nil {
		t.Fatal("an unclaimed chart/image pair must be reported; silence here is the original double-deployment bug")
	}
	if n.Excluded {
		t.Error("the advisory must not be marked as an exclusion: nothing was removed")
	}
	if !strings.Contains(n.Detail, "checkout-service") || !strings.Contains(n.Detail, "deploys-image") {
		t.Errorf("the advisory must name the image and the property to set, got %q", n.Detail)
	}
}

// A chart that does claim its image is not suspicious, and neither is an image already claimed by some other chart.
func TestVersions_NoPairWarningWhenClaimed(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{
		{
			Type: "application", Name: "checkout-service-chart", ArtefactID: "c", Group: "payments",
			Version: "1.5.0", PURL: "pkg:helm/acme/checkout-service-chart",
			Properties: []sbom.Property{
				{Name: "deploys-image", Value: "pkg:docker/acme/checkout-service"},
				{Name: "argocd_chart", Value: "checkout-service"},
			},
		},
		{
			Type: "container", Name: "checkout-service", ArtefactID: "i", Group: "payments",
			Version: "1.5.0", PURL: "pkg:docker/acme/checkout-service",
			Properties: []sbom.Property{{Name: "argocd_path", Value: "apps/checkout-service"}},
		},
	}}
	_, notices, err := Versions(Defaults(), v)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if hasReason(notices, ReasonUnclaimedPair) {
		t.Error("a chart that claims its image must not be flagged")
	}
}

// A chart whose image is not in the environment is completely ordinary. Warning about it would fire on most real data and teach operators to skim past the report.
func TestVersions_NoPairWarningWithoutAMatchingImage(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{
		{
			Type: "application", Name: "standalone-chart", ArtefactID: "c", Group: "payments",
			Version: "1.0.0", PURL: "pkg:helm/acme/standalone-chart",
			Properties: []sbom.Property{{Name: "argocd_chart", Value: "standalone"}},
		},
		{
			Type: "container", Name: "unrelated-service", ArtefactID: "i", Group: "payments",
			Version: "2.0.0", PURL: "pkg:docker/acme/unrelated-service",
			Properties: []sbom.Property{{Name: "argocd_path", Value: "apps/unrelated"}},
		},
	}}
	_, notices, err := Versions(Defaults(), v)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if hasReason(notices, ReasonUnclaimedPair) {
		t.Error("unrelated names must not be paired")
	}
}

// A misspelled property is simply an unread property, indistinguishable from never having set one.
func TestVersions_WarnsOnMisspelledClaimProperty(t *testing.T) {
	for _, typo := range []string{"deploys_image", "deploysImage", "Deploys-Image"} {
		t.Run(typo, func(t *testing.T) {
			v := &sbom.Version{Components: []sbom.Component{{
				Type: "application", Name: "chart", ArtefactID: "c", Group: "payments",
				Version: "1.0.0", PURL: "pkg:helm/acme/chart",
				Properties: []sbom.Property{
					{Name: typo, Value: "pkg:docker/acme/checkout-service"},
					{Name: "argocd_chart", Value: "chart"},
				},
			}}}
			_, notices, err := Versions(Defaults(), v)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if !hasReason(notices, ReasonClaimPropertyTypo) {
				t.Errorf("%q should be reported as a near-miss of deploys-image", typo)
			}
		})
	}
}

// The correctly spelled property must never be flagged as a typo of itself.
func TestVersions_NoTypoWarningForTheRealProperty(t *testing.T) {
	v := &sbom.Version{Components: []sbom.Component{{
		Type: "application", Name: "chart", ArtefactID: "c", Group: "payments",
		Version: "1.0.0", PURL: "pkg:helm/acme/chart",
		Properties: []sbom.Property{
			{Name: "deploys-image", Value: "pkg:docker/acme/x"},
			{Name: "argocd_chart", Value: "chart"},
		},
	}}}
	_, notices, err := Versions(Defaults(), v)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if hasReason(notices, ReasonClaimPropertyTypo) {
		t.Error("the correct spelling must not be flagged")
	}
}

func TestChartStem(t *testing.T) {
	cases := map[string]string{
		"checkout-service-chart": "checkout-service",
		"checkout-service":       "checkout-service",
		"billing_worker_chart":   "billing_worker",
		"chart-analytics":        "analytics",
		"Checkout-Service-Chart": "checkout-service",
		// "chart" alone must not reduce to nothing, or every such component would share a stem.
		"chart": "chart",
	}
	for in, want := range cases {
		if got := chartStem(in); got != want {
			t.Errorf("chartStem(%q) = %q, want %q", in, got, want)
		}
	}
}
