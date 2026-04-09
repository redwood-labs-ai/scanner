import { definePatterns } from "../types.js";

/**
 * Patterns for configuration files (YAML, JSON, Docker, etc.)
 */
export default definePatterns([
	{
		name: "Default password in config",
		regex:
			/(password|passwd|pwd|secret|token)\s*[:=]\s*['"]?(secret|password|admin|root|123456|changeme|default|test|example)['"]/gi,
		severity: "critical",
		message: "Default/weak password found in configuration",
		fix: "Use strong, unique passwords from environment variables",
		fileTypes: [".yml", ".yaml", ".env", ".toml", ".json", ".ini"],
	},
	{
		name: "Insecure shell default in env var",
		regex:
			/\$\{[A-Z_]*(PASSWORD|SECRET|TOKEN|KEY)[A-Z_]*:-(secret|password|admin|root|123456|changeme|default|test|example)[^}]*\}/gi,
		severity: "critical",
		message: "Insecure default value for sensitive environment variable",
		fix: "Remove default values for secrets or use secure defaults",
		fileTypes: [".yml", ".yaml", ".env", ".sh"],
	},
	{
		name: "Hardcoded database credentials",
		regex:
			/(DATABASE_URL|POSTGRES_PASSWORD|MYSQL_PASSWORD|REDIS_PASSWORD|MONGO_URI)\s*[:=]\s*['"]?[^${\s][^'"}\s]+['"]?/gi,
		severity: "high",
		message: "Database credentials appear to be hardcoded",
		fix: "Use environment variables or secrets management for database credentials",
		fileTypes: [".yml", ".yaml", ".env", ".toml", ".json"],
	},
	{
		name: "Exposed port 0.0.0.0",
		regex: /0\.0\.0\.0:\d+/g,
		severity: "medium",
		message: "Service bound to all interfaces (0.0.0.0) may be unintentionally exposed",
		fix: "Consider binding to 127.0.0.1 for local-only services or restrict with firewall",
		fileTypes: [".yml", ".yaml", ".toml", ".json"],
	},
	{
		name: "Privileged container",
		regex: /privileged\s*:\s*true/gi,
		severity: "high",
		message: "Container running in privileged mode has excessive host access",
		fix: "Remove privileged mode and use specific capabilities instead",
		fileTypes: [".yml", ".yaml"],
	},
	{
		name: "Host network mode",
		regex: /network_mode\s*:\s*['"]?host['"]?/gi,
		severity: "medium",
		message: "Container using host network mode bypasses network isolation",
		fix: "Use bridge networking with explicit port mappings",
		fileTypes: [".yml", ".yaml"],
	},
	{
		name: "MCP config command injection (CVE-2026-21518)",
		regex:
			/\b(?:mcpServers|servers)\b[\s\S]{0,500}?["'](?:command|args)["']\s*:\s*\[[\s\S]{0,500}?(?:\$\(|`|&&|\|\||;|\|)[\s\S]{0,200}?\]/gi,
		severity: "high",
		message:
			"MCP server config contains shell metacharacters in command/args; may enable command injection if executed via a shell",
		fix: "Avoid shell execution for MCP server commands. Pass executable + args as a safe array, disallow shell metacharacters, and prefer allowlisted binaries/paths.",
		fileTypes: [".json"],
	},
	{
		name: "MCP config uses shell wrapper (bash/sh/cmd/powershell)",
		regex:
			/\b(?:mcpServers|servers)\b[\s\S]{0,500}?["']command["']\s*:\s*["'](?:bash|sh|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?)\b[\s\S]{0,200}?["']/gi,
		severity: "high",
		message:
			"MCP server is configured to launch via a shell wrapper. This increases the risk of command injection and unexpected command parsing.",
		fix: "Prefer executing a fixed allowlisted binary directly (no shell). If a shell is unavoidable, strictly validate/escape args and disallow dynamic user input.",
		fileTypes: [".json"],
	},
	{
		name: "MCP config uses shell execution flags (-c /c -Command)",
		regex:
			/\b(?:mcpServers|servers)\b[\s\S]{0,800}?["']args["']\s*:\s*\[[\s\S]{0,800}?["'](?:-c|\/c|-Command|-EncodedCommand)["'][\s\S]{0,200}?\]/gi,
		severity: "high",
		message:
			"MCP server args include shell execution flags (-c, /c, -Command). Combined with dynamic strings this can enable RCE.",
		fix: "Avoid shell execution flags. Execute the target binary directly and pass arguments as a safe array; consider allowlisting commands and rejecting metacharacters.",
		fileTypes: [".json"],
	},
	{
		name: "MCP config runs remote package executors (npx/bunx/deno run)",
		regex:
			/\b(?:mcpServers|servers)\b[\s\S]{0,500}?["']command["']\s*:\s*["'](?:npx|bunx|deno)["']/gi,
		severity: "medium",
		message:
			"MCP server is launched via a package executor (npx/bunx/deno). This can pull and execute remote code and increases supply-chain risk.",
		fix: "Pin exact versions/hashes and prefer installing dependencies ahead of time. Avoid dynamic installs at runtime; use allowlisted sources and integrity checks.",
		fileTypes: [".json"],
	},
	{
		name: "MCP config hardcodes secrets in env",
		regex:
			/\b(?:mcpServers|servers)\b[\s\S]{0,800}?["']env["']\s*:\s*\{[\s\S]{0,1200}?["'][A-Z0-9_]*(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD)[A-Z0-9_]*["']\s*:\s*["'](?!\$\{)[^"']{6,}["'][\s\S]{0,200}?\}/gi,
		severity: "critical",
		message:
			"MCP server config appears to hardcode secrets in an env block. This risks credential leakage and accidental commits.",
		fix: "Remove hardcoded secrets from config. Reference environment variables or a secrets manager, and rotate any exposed keys.",
		fileTypes: [".json"],
	},
	{
		name: "GitHub Actions mutable tag usage (CVE-2026-33634)",
		// Typical syntax is: uses: owner/repo@v2 (no space before @)
		regex: /uses:\s*[a-z0-9_./-]+@v\d+(\.\d+)*/gi,
		severity: "high",
		message:
			"GitHub Action using mutable version tag (e.g., @v2, @v3.0). Mutable tags can be updated by action maintainers, enabling supply chain attacks as seen in CVE-2026-33634 (Trivy GitHub Action compromise)",
		fix: "Pin GitHub Actions to a specific commit SHA (40 character hash) instead of using version tags. Example: uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11",
		fileTypes: [".yml", ".yaml"],
	},
	{
		name: "Docker socket bind-mount (RED-132)",
		regex:
			/-\\s+\/var\/run\/docker\.sock[:\s]+\/var\/run\/docker\.sock|-\\s+\/var\/run\/docker\.sock|docker\.sock\\s*:\\s*docker\.sock|source:\\s*["']?\/var\/run\/docker\.sock["']?/gi,
		severity: "critical",
		message:
			"Docker socket (/var/run/docker.sock) is mounted into the container. This grants full Docker Engine API access, allowing container escape and complete host compromise",
		fix: "Never mount the Docker socket into containers. Use Docker-in-Docker (dind) with rootless Docker, gVisor, or Kata Containers for build environments. In Kubernetes, enforce Pod Security Standards to block host resource access",
		fileTypes: [".yml", ".yaml", ".json"],
	},
	{
		name: "Docker daemon TCP 2375 exposure (CVE-2025-9074)",
		regex:
			/tcp:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0):2375|:2375[^0-9]|-H\\s+tcp:\/\/[^:]+:2375|DOCKER_HOST\\s*[=:]\\s*["']?tcp:\/\/[^:]+:2375/gi,
		severity: "critical",
		message:
			"Docker daemon exposed on TCP port 2375 without TLS/authentication. As seen in CVE-2025-9074, this allows unauthenticated access to the Docker Engine API, enabling remote code execution and host compromise",
		fix: "Disable unauthenticated Docker API exposure. Use TLS certificates for remote API access. Restrict network access to port 2375 via firewall rules. Update Docker Desktop to version 4.44.3+ which fixes CVE-2025-9074",
		fileTypes: [".yml", ".yaml", ".json", ".env", ".sh", ".conf"],
	},
]);
