import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { Issue } from "./engine.js";
import {
	DEFAULT_IGNORE_DIRS,
	DEFAULT_IGNORE_EXTENSIONS,
	isIgnored,
	loadRedwoodIgnore,
} from "./ignore.js";

/**
 * Common development/test placeholder values that should never be flagged
 * as real credentials. Matched case-insensitively.
 */
const COMMON_DEV_VALUES = new Set([
	// Generic placeholders
	"password",
	"passwd",
	"changeme",
	"secret",
	"token",
	"api_key",
	"apikey",
	"placeholder",
	"example",
	"replace_me",
	"replace-me",
	"your_secret",
	"your_password",
	"your_key",
	"insert_here",
	"todo",
	"null",
	"undefined",
	// Local development
	"localdev",
	"localhost",
	"development",
	"dev",
	"test",
	"testing",
	"staging",
	"debug",
	"docker",
	"postgres",
	"mysql",
	"redis",
	"mongo",
	"admin",
	"root",
	"user",
	"guest",
	"demo",
	// Common weak/test values
	"test123",
	"123456",
	"12345678",
	"qwerty",
	"abc123",
	"letmein",
	"trustno1",
	"iloveyou",
	"password1",
	"password123",
	"admin123",
	"root123",
	"default",
	"passw0rd",
	// Keyboard patterns
	"qwertyuiop",
	"asdfghjkl",
	"zxcvbnm",
	"qweasd",
	"qweasdzxc",
]);

/**
 * Calculate Shannon entropy of a string (bits per character).
 * Real secrets typically score >3.5; common words score <3.0.
 */
function shannonEntropy(value: string): number {
	if (!value.length) return 0;
	const freq = new Map<string, number>();
	for (const ch of value) freq.set(ch, (freq.get(ch) || 0) + 1);
	let entropy = 0;
	for (const count of Array.from(freq.values())) {
		const p = count / value.length;
		entropy -= p * Math.log2(p);
	}
	return entropy;
}

/**
 * Check if a value looks like a real secret vs a dev/test placeholder.
 * Returns true if the value should be SKIPPED (i.e., it's not a real secret).
 */
function isDevPlaceholder(value: string): boolean {
	const lower = value.toLowerCase();

	// Exact match against known dev values
	if (COMMON_DEV_VALUES.has(lower)) return true;

	// All same character (e.g., "aaaaaaaa", "00000000")
	if (/^(.)\1+$/.test(lower)) return true;

	// Purely numeric sequences like "12345678"
	if (/^\d+$/.test(lower)) return true;

	// Keyboard walks
	if (/^(qwerty|asdf|zxcv)/i.test(lower)) return true;

	// Low entropy — real secrets need >3.0 bits/char
	if (shannonEntropy(value) < 3.0) return true;

	return false;
}

/**
 * Extract the value portion from a secret pattern match.
 * Handles patterns like: password: 'value', api_key = "value"
 */
function extractQuotedValue(match: string): string | null {
	const valueMatch = match.match(/['"]([^'"]+)['"]/);
	return valueMatch ? valueMatch[1] : null;
}

const SECRET_PATTERNS = [
	{
		name: "AWS Access Key",
		regex: /AKIA[0-9A-Z]{16}/g,
		severity: "critical" as const,
	},
	{
		name: "AWS Secret Key",
		// Must have context (aws/secret/key nearby) AND be exactly 40 chars base64
		// Excludes mangled symbols (start with _ or contain ::)
		regex: /(?<![A-Za-z0-9/+=_])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
		severity: "critical" as const,
		context: /aws.{0,20}secret|secret.{0,20}key|AWS_SECRET/i,
	},
	{
		name: "OpenAI API Key",
		regex: /sk-[a-zA-Z0-9]{48,}/g,
		severity: "critical" as const,
	},
	{
		name: "Anthropic API Key",
		regex: /sk-ant-[a-zA-Z0-9-]{93,}/g,
		severity: "critical" as const,
	},
	{
		name: "GitHub Token",
		regex: /ghp_[a-zA-Z0-9]{36}/g,
		severity: "critical" as const,
	},
	{
		name: "GitHub OAuth",
		regex: /gho_[a-zA-Z0-9]{36}/g,
		severity: "critical" as const,
	},
	{
		name: "Stripe Secret Key",
		regex: /sk_live_[a-zA-Z0-9]{24,}/g,
		severity: "critical" as const,
	},
	{
		name: "Stripe Publishable Key (Live)",
		regex: /pk_live_[a-zA-Z0-9]{24,}/g,
		severity: "medium" as const,
	},
	{
		name: "Private Key",
		regex: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
		severity: "critical" as const,
	},
	{
		name: "Generic API Key Assignment",
		regex:
			/(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]/gi,
		severity: "high" as const,
	},
	{
		name: "Password Assignment",
		regex: /(password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
		severity: "high" as const,
	},
	{
		name: "Bearer Token",
		regex: /bearer\s+[a-zA-Z0-9_\-.]{20,}/gi,
		severity: "high" as const,
	},
];

export async function scanSecrets(repoPath: string, changedFiles?: Set<string>): Promise<Issue[]> {
	const issues: Issue[] = [];

	// Load .redwoodignore patterns
	const ignoreConfig = await loadRedwoodIgnore(repoPath);
	const ignorePatterns = ignoreConfig?.patterns || [];

	const files = getFiles(repoPath, repoPath, ignorePatterns);

	// Filter to only changed files if diff mode
	const filesToScan = changedFiles
		? files.filter((f) => changedFiles.has(relative(repoPath, f)))
		: files;

	for (const file of filesToScan) {
		const relPath = relative(repoPath, file);

		try {
			const content = readFileSync(file, "utf-8");
			const lines = content.split("\n");

			for (const pattern of SECRET_PATTERNS) {
				let match;
				const regex = new RegExp(pattern.regex.source, pattern.regex.flags);

				while ((match = regex.exec(content)) !== null) {
					// Find line number
					const beforeMatch = content.slice(0, match.index);
					const lineNumber = beforeMatch.split("\n").length;
					const line = lines[lineNumber - 1];

					// Skip if context requirement not met
					if (pattern.context && !pattern.context.test(line)) {
						continue;
					}

					// Skip common dev/test placeholder values
					const value = extractQuotedValue(match[0]);
					if (value && isDevPlaceholder(value)) {
						continue;
					}

					// Mask the secret in output
					const masked = maskSecret(match[0]);

					issues.push({
						id: `secret-${issues.length + 1}`,
						type: pattern.name,
						severity: pattern.severity,
						file: relPath,
						line: lineNumber,
						message: `Found ${pattern.name}`,
						match: masked,
						fix: `Move this secret to an environment variable`,
					});
				}
			}
		} catch (_error) {
			// Skip files that can't be read (binary, permissions, etc.)
		}
	}

	return issues;
}

function getFiles(dir: string, repoPath: string, ignorePatterns: string[]): string[] {
	const files: string[] = [];

	try {
		const entries = readdirSync(dir);

		for (const entry of entries) {
			const fullPath = join(dir, entry);

			// Skip directories based on centralized defaults
			if (DEFAULT_IGNORE_DIRS.includes(entry)) continue;

			// Skip files with ignored extensions
			if (DEFAULT_IGNORE_EXTENSIONS.some((ext) => entry.endsWith(ext))) continue;

			// Check against .redwoodignore patterns
			if (ignorePatterns.length > 0 && isIgnored(fullPath, repoPath, ignorePatterns)) continue;

			const stat = statSync(fullPath);

			if (stat.isDirectory()) {
				files.push(...getFiles(fullPath, repoPath, ignorePatterns));
			} else if (stat.isFile()) {
				files.push(fullPath);
			}
		}
	} catch (_error) {
		// Skip directories that can't be read
	}

	return files;
}

function maskSecret(secret: string): string {
	if (secret.length <= 8) return "*".repeat(secret.length);
	return secret.slice(0, 4) + "*".repeat(secret.length - 8) + secret.slice(-4);
}
