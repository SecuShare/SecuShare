# Security Policy

## Supported Versions

SecuShare currently supports security fixes on the latest `main` branch state.

## Reporting a Vulnerability

Do not report security vulnerabilities in public GitHub issues.

Use GitHub private vulnerability reporting:

1. Open the repository **Security** tab
2. Click **Report a vulnerability**
3. Submit reproduction details, impact, and any suggested mitigation

If you cannot access the Security tab, contact the maintainers through a private GitHub security advisory draft.

## What to Include

- Affected component and version/commit
- Reproduction steps or proof of concept
- Expected vs actual behavior
- Impact assessment (confidentiality/integrity/availability)
- Suggested fix (if available)

## Dependency Vulnerability Triage

SecuShare treats dependency vulnerability scans as release controls.

- Reachable vulnerabilities are production-blocking. If `govulncheck` (or equivalent analysis) shows a vulnerable symbol is reachable from shipped code, the change or release must not proceed until the dependency is upgraded, replaced, or removed.
- Non-reachable advisories are still tracked. For each non-reachable finding, maintain a tracked record (issue/ticket) with: advisory ID, affected package/version, why it is currently non-reachable, and the planned remediation version/date.
- Non-reachable findings must be re-reviewed on each dependency update and on a regular cadence (at least monthly). If reachability changes, the finding immediately becomes blocking.
