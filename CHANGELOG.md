# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.2] - 2026-04-09

### Added

- **12 New Security Patterns**
  - Docker socket bind-mount detection (`/var/run/docker.sock`) — critical
  - Docker daemon TCP 2375 exposure (CVE-2025-9074 class) — critical
  - Go weak PRNG seeding for secrets (CVE-2026-25726 class) — critical
  - Go filesystem writes using `(r|req).URL.Path` (CVE-2026-35392 class) — critical
  - Ruby/Rails render `inline:`/`file:`/`template:` from request-derived input — critical
  - Ruby/Rails dynamic `order`/`reorder`/`group`/`having` from request-derived input — high
  - Ruby/Rails `Arel.sql(...)` from request-derived input — high
  - Ruby unsafe `Marshal.load/restore` deserialization — critical
  - Ruby SSRF via `URI.open` / `OpenURI.open_uri` from request-derived input — high
  - Ruby SSRF via `Net::HTTP.*(URI(params...))` — high
  - Ruby open redirect via `redirect_to` with request-derived input — medium
  - Ruby path traversal / arbitrary file access via `send_file` / `File.read/open` / `IO.read` with request-derived input — high

### Stats

- **91 patterns** across JS, TS, Python, Go, Ruby, PHP, Rust (up from 79 in 0.4.1)

## [0.4.1] - 2026-04-06

### Added

- **8 New Security Patterns**
  - MCP config uses shell wrapper (bash/sh/cmd/powershell) — high
  - MCP config uses shell execution flags (-c /c -Command) — high
  - MCP config runs remote package executors (npx/bunx/deno run) — medium
  - MCP config hardcodes secrets in env — critical
  - Unsafe `yaml.load()` usage (CVE-2026-24009 / Docling RCE class) — critical
  - Unsafe `tarfile.extractall()` extraction heuristic (CVE-2026-27905 class) — high
  - AWS IMDS access (169.254.169.254) — high
  - GitHub Actions mutable tag usage (CVE-2026-33634 / Trivy action compromise class) — high

### Fixed

- GitHub Actions mutable tag detector now matches the common `uses: owner/repo@v2` syntax

### Stats

- **79 patterns** across JS, TS, Python, Go, Ruby, PHP, Rust (up from 77 in 0.4.0)

## [0.4.0] - 2026-04-03

### Added

- **AI-Assisted Fixing** — Scan results now include an LLM-ready prompt you can copy directly to Claude, ChatGPT, Cursor, or any AI assistant to fix issues
  - Auto-groups findings when >20 issues for readability
  - Bypassed issues excluded from prompt
  - Use `--no-prompt` to suppress (for CI/scripted use)
  - Suppressed automatically in `--json` and `--sarif` modes

- **7 New Security Patterns**
  - Prototype pollution via convict (CVE-2026-33864) — critical
  - Prototype pollution via Object.assign — high
  - Prototype pollution via spread operator — high
  - Go path.Join without sanitization (CVE-2026-33528) — high
  - path-to-regexp multiple wildcards ReDoS (CVE-2026-4923) — high
  - path-to-regexp multi-param segments ReDoS (CVE-2026-4867) — high
  - Python webbrowser.open command injection (CVE-2026-4519) — high

### Fixed

- JSON/SARIF output is now clean (no progress messages before output)
- Spread operator pattern tightened to reduce false positives
- VERSION constant synced with package.json

### Stats

- **77 patterns** across JS, TS, Python, Go, Ruby, PHP, Rust
- By severity: Critical 23 | High 34 | Medium 10 | Low 3

## [0.3.1] - 2026-04-02

### Fixed

- Add `allowPositionals` to parseArgs config for Node.js compatibility

## [0.3.0] - 2026-03-28

### Added

- Initial public release
- Pattern detection for 70 security patterns
- Secret scanning (API keys, tokens, passwords)
- MCP server configuration validation
- Agent chain validation
- Dependency auditing
- SARIF output for CI integration
- Inline bypass comments (`// redwood-ignore`)
