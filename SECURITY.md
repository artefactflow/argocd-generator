# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately, in either of two ways:

- Through GitHub's private vulnerability reporting: open the **Security** tab of this repository and choose **Report a vulnerability**. That opens a private channel visible only to maintainers.
- By email to [security@artefactflow.com](mailto:security@artefactflow.com).

If the vulnerability is being exploited right now, or you believe a release, image or chart of this tool was not published by us, email us and begin the subject with `P1`. That reaches us at any hour. Please use it only for that.

Include what you did, what happened, and what you expected. A minimal reproduction is worth more than anything else. You will get an acknowledgement, and we will keep you updated as the report is triaged and fixed. Please give us a chance to ship a fix before disclosing publicly.

Our [Vulnerability Disclosure Policy](https://www.artefactflow.com/legal) covers this tool: what is in scope, what we commit to, and the safe harbour for good-faith research. Test against your own installation only, never against a cluster that is not yours.

## Security advisories

Fixed vulnerabilities are published as GitHub Security Advisories on this repository, stating the affected and fixed versions and what to do. They also reach the GitHub Advisory Database, so Dependabot and other scanners can alert you. Watch this repository for security alerts to hear about them directly.

When there is something you can do before a fix is ready, such as avoiding a version or rotating a credential, the advisory says so straight away and is updated when the fix is released.

## Verifying a release

Every published image carries a build provenance attestation from this repository's release workflow, and each GitHub release has a CycloneDX SBOM per platform attached. To check that an image was built by us:

```sh
gh attestation verify oci://ghcr.io/artefactflow/argocd-generator:<version> --repo artefactflow/argocd-generator
```

An image that fails this check was not published by us. Report it as described above, with `P1`.

## Supported versions

Fixes go onto the newest release. The container image and the Helm chart share one version, so upgrading the chart to the fixed version installs the fixed image. The raw manifests in `deploy/` reference the `latest` image tag, which always follows the newest full release (never a pre-release).

## Handling of credentials

Two independent credentials are in play when the generator runs as an ApplicationSet plugin:

- The **plugin token** (`ARGOCD_PLUGIN_TOKEN`) is what the ApplicationSet controller presents to the plugin. Requests without it are refused.
- The **service account** (`ARTEFACTFLOW_CLIENT_ID` / `ARTEFACTFLOW_CLIENT_SECRET`) is what the plugin presents to ArtefactFlow. The controller never sees it. Give the service account read access only to the SBOMs and environments it has to render.

An already-minted bearer token is deliberately not accepted. It would make it easy to run the generator as a human user, carrying that person's full scope set.

The container runs as an unprivileged user on a minimal distroless image. The Helm chart and the manifests in `deploy/` include a `NetworkPolicy` that admits only the ApplicationSet controller; keep it in place.
