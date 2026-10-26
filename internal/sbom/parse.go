package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Parse decodes an SBOM version document, tolerating unknown fields. It validates only what the generator relies on: that the document is CycloneDX.
func Parse(data []byte) (*Version, error) {
	var v Version
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("parse sbom version: %w", err)
	}
	if !strings.EqualFold(v.BOMFormat, "CycloneDX") {
		return nil, fmt.Errorf("unexpected bomFormat %q, want CycloneDX", v.BOMFormat)
	}
	return &v, nil
}
