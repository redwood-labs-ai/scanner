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

- **No inline ignores yet**: `// redwood-ignore-next-line` support is planned for a future release.

## License

MIT © Redwood Labs
