# Changelog

## [0.2.0] - 2026-03-29

### Added
- **Config file support** — `.redwoodrc.json` or `.redwoodrc.yaml` for project-level configuration
- **`--severity` flag** — Set minimum severity threshold for exit code failures (critical/high/medium/low)
- **Inline ignore comments** — Suppress findings with `// redwood-ignore` or `# redwood-ignore`
- **JSON schema** — IDE autocomplete for config files (`schema/redwoodrc.json`)
- **Configurable scanners** — Enable/disable individual scanners via config
- **Custom severity per rule** — Override default severity levels in config
- **Max findings limit** — Cap findings per rule type to reduce noise
- **Comprehensive unit tests** — 23 tests covering pattern detection
- **minimatch ReDoS pattern** — Detects CVE-2026-27904 (nested extglob vulnerability)
- **path-to-regexp ReDoS pattern** — Detects CVE-2026-4926 (sequential optional groups)

### Changed
- Upgraded glob from 10.x to 13.x (fixes deprecation warnings)
- Centralized IGNORE_DIRS across all scanners for consistency
- Added Biome for code formatting and linting

### Fixed
- Skip pattern definition files to reduce self-scan false positives
- Improved SQL injection pattern to avoid false positives

## [0.1.1] - 2026-03-15

### Fixed
- SQL injection false positive fix

## [0.1.0] - 2026-03-01

### Added
- Initial release
- Pattern detection (500+ patterns across JS, TS, Python, Rust, Go, Ruby, PHP)
- Secret scanning
- MCP security validation
- Dependency audit
- Agent chain validation
- SARIF output support
- CLI with `redwood scan` command
