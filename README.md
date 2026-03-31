# 🌲 Redwood Scanner

Security scanner for AI-native codebases. Catches vulnerabilities, dangerous patterns, and agent orchestration issues.

## Features

- **Pattern Detection** — 500+ security patterns across JS, TS, Python, Rust, Go, Ruby, PHP
- **Secret Scanning** — API keys, tokens, passwords, private keys
- **MCP Security** — Validates MCP server configurations and tool chains
- **Dependency Audit** — Checks for known vulnerabilities
- **Agent Chain Validation** — Analyzes multi-agent orchestration for security gaps

## Installation

```bash
npm install -g @redwood-labs/scanner
```

Or use with npx:
```bash
npx @redwood-labs/scanner scan .
```

## CLI Usage

### Full Security Scan
```bash
redwood scan ./my-repo
```

### Custom Config File
```bash
# Use a custom config file
redwood scan ./my-repo --config /path/to/.redwoodrc.json

# Use YAML config
redwood scan ./my-repo --config .redwoodrc.yaml
```

### Agent Chain Validation
```bash
redwood agent-chain ./my-repo
```

### Output Formats
```bash
# JSON output
redwood scan ./my-repo --json

# SARIF format (for GitHub/GitLab integration)
redwood scan ./my-repo --sarif > results.sarif
```

### Severity Threshold
```bash
# Fail on medium or higher severity
redwood scan ./my-repo --severity medium
```

## Programmatic Usage

```typescript
import { scan, validateAgentChain } from '@redwood-labs/scanner';

// Full security scan
const issues = await scan('./my-repo', { verbose: true });

// Filter by severity
const critical = issues.filter(i => i.severity === 'critical');

// Agent chain validation only
const chainIssues = await validateAgentChain('./my-repo');
```

## CI Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    npx @redwood-labs/scanner scan . --sarif > results.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Forgejo/Gitea Actions
```yaml
- name: Security Scan
  run: |
    npm install -g @redwood-labs/scanner
    redwood scan .
```

## Exit Codes

- `0` — No critical issues found
- `1` — Critical issues detected

## Configuration

Create a `.redwoodrc.json` or `.redwoodrc.yaml` file in your project root to customize scanner behavior:

### Example `.redwoodrc.json`
```json
{
  "severity": "high",
  "ignore": [
    "**/node_modules/**",
    "**/dist/**",
    "**/*.test.ts"
  ],
  "scanners": {
    "secrets": true,
    "dependencies": true,
    "patterns": true,
    "mcp": true,
    "agentChain": true
  },
  "rules": {
    "hardcoded-secret": "critical",
    "insecure-endpoint": "high"
  },
  "maxFindings": 50,
  "output": {
    "json": false,
    "verbose": false
  },
  "skipDirs": ["vendor", "third_party"]
}
```

### Example `.redwoodrc.yaml`
```yaml
severity: high

ignore:
  - '**/node_modules/**'
  - '**/dist/**'
  - '**/*.test.ts'

scanners:
  secrets: true
  dependencies: true
  patterns: true
  mcp: true
  agentChain: true

rules:
  hardcoded-secret: critical
  insecure-endpoint: high

maxFindings: 50

output:
  json: false
  verbose: false

skipDirs:
  - vendor
  - third_party
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `severity` | string | `"critical"` | Minimum severity to fail scan (`critical`/`high`/`medium`/`low`/`info`) |
| `ignore` | string[] | `[]` | Glob patterns for files to ignore |
| `scanners` | object | `{}` | Enable/disable specific scanners (all enabled by default) |
| `scanners.secrets` | boolean | `true` | Enable secrets scanning |
| `scanners.dependencies` | boolean | `true` | Enable dependency scanning |
| `scanners.patterns` | boolean | `true` | Enable code pattern analysis |
| `scanners.mcp` | boolean | `true` | Enable MCP server scanning |
| `scanners.agentChain` | boolean | `true` | Enable agent chain validation |
| `rules` | object | `{}` | Override severity per rule type |
| `maxFindings` | number | `100` | Maximum findings per rule type |
| `output.json` | boolean | `false` | Output results as JSON |
| `output.sarif` | boolean | `false` | Output results in SARIF format |
| `output.verbose` | boolean | `false` | Show detailed output |
| `skipDirs` | string[] | `[]` | Additional directories to skip |

### Custom Config Path

Use `--config` to specify a custom config file location:
```bash
redwood scan ./my-repo --config /path/to/.redwoodrc.json
```

CLI options always override config file settings.

Create `.redwoodignore` in your repo root:
```
# Build output
dist/
build/

# Test fixtures
test/fixtures/

# Dependencies
node_modules/
```

## Inline Ignore Comments

Suppress specific findings with inline comments:

```javascript
// redwood-ignore: intentional for testing
eval(userInput);

// redwood-ignore
const token = "sk-test-123";
```

Supported comment styles:
- `// redwood-ignore` for JS, TS, PHP, Go, Rust
- `# redwood-ignore` for Python, Ruby, YAML, Shell
- Add optional reason: `// redwood-ignore: reason here`

## What It Catches

| Category | Examples |
|----------|----------|
| **Injection** | SQL injection, command injection, XSS, SSTI |
| **Secrets** | API keys, tokens, passwords, private keys |
| **Crypto** | Weak algorithms, insecure random, disabled TLS |
| **Auth** | Hardcoded credentials, timing attacks |
| **MCP** | Dangerous tools, missing validation |
| **Dependencies** | Known CVEs, outdated packages |
| **Agent Chains** | Privilege escalation, context leaks |

## Known Limitations

- **Inline ignores**: Use `// redwood-ignore` or `# redwood-ignore` to suppress specific findings. In critical mode, use `--bypass-ignore` flag to include bypassed findings as high-severity issues.

## License

MIT © Redwood Labs
