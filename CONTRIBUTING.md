# Contributing to SecuShare

Thank you for your interest in contributing to SecuShare! This document provides guidelines and instructions for contributing.

## Development Setup

1. Fork and clone the repository
2. Set up the development environment as described in README.md
3. Create a feature branch: `git checkout -b feature/your-feature-name`

## Code Style

### Go (Backend)
- Use `gofmt` for formatting
- Follow [Effective Go](https://golang.org/doc/effective_go) guidelines
- Run `go vet` before committing

### TypeScript/React (Frontend)
- Use the existing ESLint configuration
- Run `npm run lint` before committing
- Use TypeScript strict mode

## Testing

### Backend
```bash
cd backend
go test ./...
```

### Frontend
```bash
cd frontend
npm run test
```

## Pull Request Process

1. Ensure all tests pass
2. Update documentation if needed
3. Add tests for new features
4. Keep PRs focused and reasonably sized
5. Write clear commit messages

## Security Issues

**Do not open public issues for security vulnerabilities.**

Use GitHub's private vulnerability reporting:
1. Open the repository's **Security** tab
2. Click **Report a vulnerability**
3. Submit details privately

If the Security tab is unavailable, open a private GitHub security advisory draft and request maintainer access.

## Questions?

Open a GitHub Discussion for general questions or clarification.
