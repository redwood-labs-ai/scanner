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
			/(DATABASE_URL|POSTGRES_PASSWORD|MYSQL_PASSWORD|REDIS_PASSWORD|MONGO_URI)\s*[:=]\s*['"]?(?!localdev|localhost|development|dev$|test$|testing|staging|docker|changeme|password$|secret$|admin$|placeholder|demo$)[^${\s][^'"}\s]+['"]?/gi,
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
	{
		name: ".env file with AWS access keys (RED-162)",
		regex:
			/\b(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*[:=]\s*['"]?[A-Z0-9]{14,}['"]?/gi,
		severity: "critical",
		message:
			"AWS credentials found in .env file. AWS access keys committed to version control can lead to full account compromise, unauthorized resource access, and significant financial damage",
		fix: "Remove hardcoded AWS credentials immediately. Use IAM roles, AWS Secrets Manager, SSM Parameter Store, or instance profiles for authentication. Rotate any potentially exposed keys",
		fileTypes: [".env"],
	},
	{
		name: ".env file with Slack webhook/bot token (RED-162)",
		regex:
			/\b(?:SLACK_WEBHOOK_URL|SLACK_BOT_TOKEN|SLACK_SIGNING_SECRET)\s*[:=]\s*['"]?(?:https?:\/\/hooks\.slack\.com\/services\/|xox[bpsr]-)[^'"]{10,}['"]?/gi,
		severity: "high",
		message:
			"Slack webhook URL or bot token found in .env file. Exposed Slack credentials can be used to send unauthorized messages, exfiltrate data, or disrupt team communications",
		fix: "Remove Slack credentials from .env files. Use CI/CD secrets management or environment variable injection at runtime. Rotate any exposed tokens immediately",
		fileTypes: [".env"],
	},
	{
		name: ".env file with Stripe payment key (RED-162)",
		regex:
			/\b(?:STRIPE_SECRET_KEY|STRIPE_WEBHOOK_SECRET|STRIPE_SIGNING_SECRET)\s*[:=]\s*['"]?(?:sk_|rk_)[A-Za-z0-9]{20,}['"]?/gi,
		severity: "critical",
		message:
			"Stripe payment secret key found in .env file. Exposed Stripe keys can lead to unauthorized financial transactions, PCI DSS compliance violations, and customer data exposure",
		fix: "Never commit Stripe secrets to version control. Use Stripe's environment variable injection in CI/CD. Rotate any exposed keys immediately. Use test keys during development",
		fileTypes: [".env"],
	},
	{
		name: ".env file with generic secret/token/key (RED-162)",
		regex:
			/\b(?:SECRET|TOKEN|API_KEY|PRIVATE_KEY|SIGNING_SECRET|ENCRYPTION_KEY|AUTH_KEY)\s*[:=]\s*['"]?(?!(?:secret|password|admin|root|123456|changeme|default|test|example|placeholder|your_|change_this)[^'"]*['"]?(?=\s*$|\s*#))[a-zA-Z0-9/+=_\-]{20,}/gi,
		severity: "high",
		message:
			"Generic secret token/key with a real value (16+ chars, not a placeholder) found in .env file. Long non-placeholder values indicate actual credentials that should not be committed",
		fix: "Replace with environment variable references (${VAR_NAME}). Rotate any potentially exposed keys. Use a secrets manager like HashiCorp Vault, AWS Secrets Manager, or Doppler",
		fileTypes: [".env"],
	},
	{
		name: ".env file with GitHub token (RED-162)",
		regex:
			/\b(?:GITHUB_TOKEN|GITHUB_API_KEY|GH_TOKEN|GH_ENTERPRISE_TOKEN)\s*[:=]\s*['"]?(?:gh[ps]_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9]{20,}_[A-Za-z0-9]{20,})['"]?/gi,
		severity: "critical",
		message:
			"GitHub personal access token found in .env file. Exposed tokens can lead to unauthorized repository access, code injection, supply chain attacks, and data exfiltration",
		fix: "Rotate the exposed GitHub token immediately via GitHub UI. Use GitHub Apps with fine-grained permissions instead of PATs. Store in secrets manager. Consider using sboms or GitHub's token rotation APIs",
		fileTypes: [".env"],
	},
	{
		name: ".env file with Google Cloud credentials (RED-162)",
		regex:
			/\\b(?:GOOGLE_SERVICE_ACCOUNT_KEY|GOOGLE_API_KEY|GOOGLE_CLIENT_SECRET|SERVICE_ACCOUNT_JSON)\\s*[:=]\\s*['\"]?(?:\\{[\\s\\S]*?(?:\"project_id\"|\"private_key\")|AIza[A-Za-z0-9_-]{35})['\"]?/gs,
		severity: "critical",
		message:
			"Google Cloud credentials found in .env file. Service account keys and API keys can provide full access to GCP resources, billing, and data",
		fix: "Use Google Cloud Workload Identity or instance metadata instead of service account keys. Never commit keys to version control. Use short-lived credentials and least-privilege service accounts",
		fileTypes: [".env"],
	},
	{
		name: ".env file with generic password/credentials (RED-162)",
		regex:
			/\b(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|MONGO_PASSWORD|REDIS_PASSWORD|RABBITMQ_DEFAULT_PASS|ADMIN_PASSWORD|ROOT_PASSWORD|JWT_SECRET|SESSION_SECRET|COOKIE_SECRET)\s*[:=]\s*['"]?(?!\$|${|<).*[^'"]{8,}['"]?/gi,
		severity: "high",
		message:
			"Hardcoded database or session password found in .env file. Credentials should never be stored in version control",
		fix: "Use environment variable references (${DB_PASSWORD}) or a secrets manager. For local development, use empty values or placeholders. Never commit real passwords",
		fileTypes: [".env"],
	},
	{
		name: ".env file with Docker registry credentials (RED-162)",
		regex:
			/\b(?:DOCKER_PASSWORD|REGISTRY_PASSWORD|DOCKER_HUB_PASSWORD|HARBOR_PASSWORD)\s*[:=]\s*['"]?(?!\$|${|<).*[^'"]{6,}['"]?/gi,
		severity: "high",
		message:
			"Docker registry credentials found in .env file. Exposed credentials can allow unauthorized access to container images and supply chain attacks",
		fix: "Use Docker login via CI/CD secrets, not hardcoded credentials. Consider using Docker content trust and signature verification",
		fileTypes: [".env"],
	},
	{
		name: ".env file with Azure client credentials (RED-162)",
		regex:
			/\b(?:AZURE_CLIENT_SECRET|AZURE_CLIENT_ID)\s*[:=]\s*['"]?(?!\$|\$\{)[^'"]{8,}['"]?/gi,
		severity: "high",
		message:
			"Azure client credentials found in .env file. Exposed secrets can lead to unauthorized access to cloud resources and billing abuse",
		fix: "Use managed identities, Azure Key Vault, or workload identity. Never commit Azure secrets",
		fileTypes: [".env", ".env.local", ".env.production", ".env.development"],
	},
	{
		name: ".env file with Azure subscription/tenant IDs (RED-162)",
		regex:
			/\b(?:AZURE_TENANT_ID|AZURE_SUBSCRIPTION_ID)\s*[:=]\s*['"]?(?!\$|\$\{)[^'"]{8,}['"]?/gi,
		severity: "medium",
		message:
			"Azure tenant or subscription ID in .env file. While not secret, these identifiers can aid reconnaissance",
		fix: "Use environment variable references for configuration portability",
		fileTypes: [".env", ".env.local", ".env.production", ".env.development"],
	},
]);
