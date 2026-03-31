import { definePatterns } from "../types.js";

export default definePatterns([
	{
		name: "Go SQL injection",
		regex:
			/\.(Query|QueryRow|Exec)\s*\(\s*["'`].*\+|fmt\.Sprintf\s*\(\s*["'`].*SELECT|fmt\.Sprintf\s*\(\s*["'`].*INSERT|fmt\.Sprintf\s*\(\s*["'`].*UPDATE|fmt\.Sprintf\s*\(\s*["'`].*DELETE/gi,
		severity: "critical",
		message: "SQL query built with string concatenation/formatting",
		fix: "Use parameterized queries with ? or $1 placeholders",
		fileTypes: [".go"],
	},
	{
		name: "Go command injection",
		regex: /exec\.Command\s*\(\s*["'][^"']*["']\s*\+|exec\.Command\s*\([^)]*fmt\.Sprintf/g,
		severity: "critical",
		message: "Command execution with potentially user-controlled input",
		fix: "Validate and sanitize input, avoid shell execution",
		fileTypes: [".go"],
	},
	{
		name: "Go TLS skip verify",
		regex: /InsecureSkipVerify\s*:\s*true/g,
		severity: "high",
		message: "TLS certificate verification disabled",
		fix: "Remove InsecureSkipVerify or set to false",
		fileTypes: [".go"],
	},
	{
		name: "Go unsafe package",
		regex: /import\s+["']unsafe["']|unsafe\.Pointer/g,
		severity: "medium",
		message: "Unsafe package usage bypasses Go memory safety",
		fix: "Avoid unsafe unless absolutely necessary; document why",
		fileTypes: [".go"],
	},
	{
		name: "Go hardcoded credentials",
		regex: /(password|secret|apikey|api_key|token)\s*[:=]\s*["'][^"']{8,}["']/gi,
		severity: "high",
		message: "Potential hardcoded credentials",
		fix: "Use environment variables or secrets management",
		fileTypes: [".go"],
	},
	{
		name: "Go path traversal",
		regex: /filepath\.Join\s*\([^)]*\+|os\.(Open|ReadFile|WriteFile)\s*\([^)]*\+/g,
		severity: "high",
		message: "File path with user-controlled input may allow traversal",
		fix: "Use filepath.Clean and validate path does not escape base directory",
		fileTypes: [".go"],
	},
	{
		name: "Go SSRF",
		regex: /http\.(Get|Post|Head)\s*\([^"'`]|http\.NewRequest\s*\([^)]*\+/g,
		severity: "high",
		message: "HTTP request with potentially user-controlled URL",
		fix: "Validate and whitelist allowed URL schemes and hosts",
		fileTypes: [".go"],
	},
]);
