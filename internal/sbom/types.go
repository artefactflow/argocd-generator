// Package sbom holds a deliberately tolerant subset of the CycloneDX SBOM version document returned by the ArtefactFlow API. Only the fields the generator consumes are modelled, so a CycloneDX minor-version bump or an added field does not break parsing.
package sbom

// Version is one SBOM version document (the shape returned by GET /v1/sboms/{sbomName}/versions/{versionValue}).
type Version struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     string      `json:"version"`
	Components  []Component `json:"components"`
}

// Component is a single deployable/inventory entry. Every field is resolved from the artefact catalog upstream; Properties and ExternalReferences carry the merged artefact+version metadata (version wins on key conflict).
type Component struct {
	ArtefactID         string              `json:"artefact_id"`
	BOMRef             string              `json:"bom-ref"`
	Type               string              `json:"type"`
	Name               string              `json:"name"`
	Group              string              `json:"group"`
	Version            string              `json:"version"`
	PURL               string              `json:"purl"`
	Source             string              `json:"source"`
	Properties         []Property          `json:"properties"`
	ExternalReferences []ExternalReference `json:"external_references"`
}

// Property is a CycloneDX name-value property.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ExternalReference is a CycloneDX external reference.
type ExternalReference struct {
	Type    string `json:"type"`
	URL     string `json:"url"`
	Comment string `json:"comment"`
}

// Prop returns the value of the named property and whether it was present.
func (c Component) Prop(name string) (string, bool) {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value, true
		}
	}
	return "", false
}
