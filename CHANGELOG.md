# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
