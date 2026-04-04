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
]);
