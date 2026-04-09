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
		name: "Go path.Join without sanitization (CVE-2026-33528)",
		regex:
			/filepath\.Join\s*\(\s*\w+\s*,\s*\w+\s*\)|filepath\.Join\s*\(\s*["'][^"']*["']\s*,\s*[a-zA-Z_]/g,
		severity: "high",
		message:
			"path.Join with unsanitized input allows path traversal. Similar to CVE-2026-33528 in GoDoxy where user-controlled filename parameter bypassed directory restrictions",
		fix: "Validate and sanitize path input before using path.Join. Use filepath.Clean(), then verify the result starts with the base directory. Consider using path/filepath.EvalSymlinks for additional safety",
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
	{
		name: "Go weak PRNG seeding for secrets (CVE-2026-25726)",
		regex:
			/math\/rand\s*\.\s*New\s*\(\s*math\/rand\.NewSource\s*\(\s*time\.Now\s*\(\)\.UnixNano\s*\(\)\s*\)|rand\.Seed\s*\(\s*time\.Now\s*\(\)\.UnixNano\s*\(\)\s*\)/g,
		severity: "critical",
		message:
			"Weak PRNG seeding using math/rand with time.Now().UnixNano() for security-sensitive operations. As seen in CVE-2026-25726 (Cloudreve), this allows attackers to predict secrets by brute-forcing the timestamp seed, leading to JWT forgery and account takeover",
		fix: "Use crypto/rand for cryptographic randomness. Replace math/rand with crypto/rand.Read() or crypto/rand.Int() for generating secrets, tokens, and keys",
		fileTypes: [".go"],
	},
	{
		name: "Go filesystem writes using r.URL.Path (CVE-2026-35392)",
		regex:
			/os\.(Open|Create|WriteFile|ReadFile)\s*\([^)]*r\.URL\.Path|io\.CopyFile\s*\([^)]*r\.URL\.Path|filepath\.Join\s*\([^)]*r\.URL\.Path/g,
		severity: "critical",
		message:
			"Filesystem operation using unsanitized r.URL.Path allows path traversal attacks. As seen in CVE-2026-35392 (goshs), this enables arbitrary file write/overwrite on the server",
		fix: "Never use r.URL.Path directly for filesystem operations. Sanitize input with filepath.Clean(), validate the result stays within the intended base directory, and reject paths containing '..' or absolute paths",
		fileTypes: [".go"],
	},
]);
