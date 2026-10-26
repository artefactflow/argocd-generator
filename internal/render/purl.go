package render

import (
	"net/url"
	"strings"
)

// parsePURL splits a Package URL into its type and its namespace/name path. It handles the common shape pkg:type/namespace/name@version(?qualifiers)(#subpath). The path segments are percent-decoded. Both return values are empty for a string that is not a PURL.
func parsePURL(purl string) (typ, path string) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", ""
	}
	// Drop qualifiers (?k=v), subpath (#...) and the version suffix (@version).
	rest, _, _ = strings.Cut(rest, "?")
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "@")

	typ, rest, ok = strings.Cut(rest, "/")
	typ = strings.ToLower(strings.TrimSpace(typ))
	if !ok || rest == "" {
		return typ, ""
	}

	segs := strings.Split(rest, "/")
	for i, s := range segs {
		if dec, err := url.PathUnescape(s); err == nil {
			segs[i] = dec
		}
	}
	return typ, strings.Join(segs, "/")
}

// imageRepositoryFromPURL returns a container image repository for OCI-style PURLs (docker, oci) and an empty string for any other type. A non-container PURL (for example pkg:npm/...) does not identify a runnable image, so emitting its namespace/name as an "image" would be misleading; callers get an empty repository and the raw purl/purl_type parameters to decide what to do.
func imageRepositoryFromPURL(purl string) string {
	typ, path := parsePURL(purl)
	switch typ {
	case "docker", "oci":
		return path
	default:
		return ""
	}
}
