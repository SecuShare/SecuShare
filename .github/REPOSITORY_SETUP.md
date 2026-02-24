# GitHub Repository Setup Checklist

Use this checklist after creating/publishing the GitHub repository.

## 1) Repository Metadata

- Description:
  `Secure end-to-end encrypted file sharing with client-side cryptography (React + Go).`
- Website:
  your production/public project URL (optional)
- Topics:
  `e2ee`, `file-sharing`, `zero-knowledge`, `react`, `typescript`, `go`, `fiber`, `sqlite`, `webcrypto`, `security`

If your repository slug is not `SecuShare/SecuShare`, update release links in `CHANGELOG.md`.

## 2) Branch Protection (default branch)

Enable branch protection for the default branch and require:

- Pull request before merge
- At least 1 approving review
- Dismiss stale approvals on new commits
- Conversation resolution before merge
- Require status checks to pass before merge:
  - `Backend Lint`
  - `Backend Test`
  - `Backend Build`
  - `Frontend Lint`
  - `Frontend Test`
  - `Frontend Build`
  - `Security Scan`
  - `Docker Build Test`
- Require branches to be up to date before merging
- Restrict force pushes
- Restrict branch deletion

Recommended:

- Require signed commits
- Include administrators in branch protection

## 3) Security Features

Enable in repository settings:

- Private vulnerability reporting
- Dependabot alerts
- Dependabot security updates

Repository policy files are already present:

- `SECURITY.md` (reporting policy)
- `.github/dependabot.yml` (dependency update automation)

## 4) Optional Security Hardening

- Enable secret scanning (and push protection, if available)
- Enable code scanning alerts
- Enable dependency graph
