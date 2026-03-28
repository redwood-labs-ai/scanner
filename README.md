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
npm install -g @redwoodlabs/scanner
```

Or use with npx:
```bash
npx @redwoodlabs/scanner scan .
```

## CLI Usage

### Full Security Scan
```bash
redwood scan ./my-repo
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

## Programmatic Usage

```typescript
import { scan, validateAgentChain } from '@redwoodlabs/scanner';

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
    npx @redwoodlabs/scanner scan . --sarif > results.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Forgejo/Gitea Actions
```yaml
- name: Security Scan
  run: |
    npm install -g @redwoodlabs/scanner
    redwood scan .
```

## Exit Codes

- `0` — No critical issues found
- `1` — Critical issues detected

## Ignoring Files

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

## License

MIT © Redwood Labs
