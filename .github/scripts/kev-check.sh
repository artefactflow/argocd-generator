#!/usr/bin/env bash
# Fails when a Trivy JSON report contains a vulnerability listed in CISA's Known Exploited Vulnerabilities (KEV) catalogue.
#
# A KEV listing means the vulnerability is being exploited in the wild, so a hit is never a finding to schedule: it is a security problem to handle now. Other findings are listed in the job summary but do not fail the run; the weekly Dependabot updates of the base images and Go toolchain are what clear those.
#
# This script is kept identical in every ArtefactFlow integration repository. Change it in all of them at once.
#
# Usage: kev-check.sh <trivy-report.json> [kev-catalogue.json]
# Without a catalogue file the current catalogue is downloaded from CISA.
set -euo pipefail

report="${1:?usage: kev-check.sh <trivy-report.json> [kev-catalogue.json]}"
catalogue="${2:-}"

if [ -z "$catalogue" ]; then
  catalogue="$(mktemp)"
  if ! curl -sSfL --retry 3 --retry-all-errors -o "$catalogue" https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json; then
    echo "::error::could not download CISA's Known Exploited Vulnerabilities catalogue, so the image could not be checked against it. Re-run the job; this check fails closed."
    exit 1
  fi
fi

# A truncated or empty catalogue would pass every finding, so refuse one that does not look like the real thing. The real catalogue held 1,723 entries on 2026-09-25 and only grows.
if ! jq -e '(.vulnerabilities | type) == "array" and (.vulnerabilities | length) > 1000' "$catalogue" >/dev/null 2>&1; then
  echo "::error::the Known Exploited Vulnerabilities catalogue is not in the expected format or is implausibly small; refusing to treat the image as clean."
  exit 1
fi

# A report without scan targets says nothing about the image. A real report of these images always has at least the OS target.
if ! jq -e 'type == "object" and .SchemaVersion == 2 and (.Results | type) == "array" and (.Results | length) > 0' "$report" >/dev/null 2>&1; then
  echo "::error::$report is not a Trivy JSON report with scan results; refusing to treat the image as clean."
  exit 1
fi

# All classification happens in jq, so no field is ever split by the shell: an empty value cannot shift the columns and hide a hit.
findings="$(jq -c --slurpfile kev "$catalogue" '
  ($kev[0].vulnerabilities | map({key: .cveID, value: .dateAdded}) | from_entries) as $known
  | [.Results[]?.Vulnerabilities[]?
     | {id: .VulnerabilityID,
        pkg: (.PkgName // "unknown"),
        installed: (.InstalledVersion // "" | if . == "" then "unknown" else . end),
        fixed: (.FixedVersion // "" | if . == "" then "none" else . end),
        added: ($known[.VulnerabilityID] // null)}]
  | unique' "$report")"

total="$(jq 'length' <<< "$findings")"
hits="$(jq '[.[] | select(.added != null)] | length' <<< "$findings")"

jq -r '.[] | select(.added != null)
  | "::error::\(.id) in \(.pkg) \(.installed) is on CISA'"'"'s Known Exploited Vulnerabilities catalogue (listed \(.added), fixed in: \(.fixed)). Treat it as a security report under SECURITY.md, not as a routine update."' <<< "$findings"

{
  echo "### Known vulnerabilities"
  echo
  if [ "$total" -eq 0 ]; then
    echo "No known vulnerabilities."
  else
    echo "$total finding(s), $hits on CISA's Known Exploited Vulnerabilities catalogue."
    echo
    echo "| Vulnerability | Package | Installed | Fixed in | Exploited (KEV) |"
    echo "|---|---|---|---|---|"
    jq -r '.[] | "| \(.id) | \(.pkg) | \(.installed) | \(.fixed) | \(if .added then "**yes** (listed \(.added))" else "no" end) |"' <<< "$findings"
  fi
} >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"

if [ "$hits" -gt 0 ]; then
  exit 1
fi
echo "No finding is on the Known Exploited Vulnerabilities catalogue ($total finding(s) in total)."
