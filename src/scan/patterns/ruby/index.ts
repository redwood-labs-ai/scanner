import { definePatterns } from "../types.js";

export default definePatterns([
	{
		name: "Ruby command injection",
		regex: /system\s*\(|exec\s*\(|`[^`]*#\{|%x\{|Open3\.(capture|popen)/g,
		severity: "critical",
		message: "Command execution that may include user input",
		fix: "Use array form of system/exec to avoid shell interpolation",
		fileTypes: [".rb", ".erb"],
	},
	{
		name: "Ruby eval injection",
		regex: /\beval\s*\(|instance_eval|class_eval|module_eval/g,
		severity: "critical",
		message: "Dynamic code evaluation is dangerous with user input",
		fix: "Avoid eval; use safer alternatives like case/when or method dispatch",
		fileTypes: [".rb", ".erb"],
	},
	{
		name: "Ruby send injection",
		regex: /\.send\s*\(|\.public_send\s*\(|\.try\s*\(/g,
		severity: "high",
		message: "Dynamic method invocation may allow arbitrary method calls",
		fix: "Whitelist allowed method names before using send",
		fileTypes: [".rb", ".erb"],
	},
	{
		name: "Ruby YAML deserialization",
		regex: /YAML\.load\s*\(|Psych\.load\s*\(/g,
		severity: "critical",
		message: "YAML.load can execute arbitrary code via deserialization",
		fix: "Use YAML.safe_load instead of YAML.load",
		fileTypes: [".rb"],
	},
	{
		name: "Ruby SQL injection",
		regex:
			/\.where\s*\(\s*["'][^"']*#\{|\.find_by_sql\s*\(\s*["'][^"']*#\{|\.execute\s*\(\s*["'][^"']*#\{/g,
		severity: "critical",
		message: "SQL query with string interpolation is vulnerable to injection",
		fix: 'Use parameterized queries: where("col = ?", value)',
		fileTypes: [".rb"],
	},
	{
		name: "Ruby ERB injection",
		regex: /ERB\.new\s*\(|render\s+inline\s*:/g,
		severity: "high",
		message: "Dynamic ERB rendering may allow template injection",
		fix: "Use static templates; never pass user input to ERB.new",
		fileTypes: [".rb"],
	},
	{
		name: "Ruby/Rails render inline/file/template from request params",
		regex: /\brender\s*\(?\s*(inline|file|template):\s*(params|request\.params|cookies|session)\b/g,
		severity: "critical",
		message:
			"Rendering templates directly from request-derived input can enable template injection or path traversal",
		fix: "Never render inline/file/template from user input. Use a strict allowlist of template names/paths.",
		fileTypes: [".rb"],
	},
	{
		name: "Ruby/Rails SQL injection via dynamic ORDER/GROUP/HAVING",
		regex: /\.(order|reorder|group|having)\(\s*(params|request\.params|cookies|session)\b/g,
		severity: "high",
		message:
			"ActiveRecord order/group/having with request-derived input can allow SQL injection via SQL fragments",
		fix: "Use a strict allowlist for sort/group fields; prefer hash-style order().",
		fileTypes: [".rb"],
	},
	{
		name: "Ruby/Rails Arel.sql with request-derived input",
		regex: /Arel\.sql\(\s*(params|request\.params|cookies|session)\b/g,
		severity: "high",
		message: "Arel.sql disables sanitization; request-derived input here can become raw SQL",
		fix: "Only use Arel.sql with constant strings or allowlisted values.",
		fileTypes: [".rb"],
	},
	{
		name: "Ruby unsafe Marshal deserialization",
		regex: /\bMarshal\.(load|restore)\s*\(/g,
		severity: "critical",
		message:
			"Marshal.load/restore on untrusted data can lead to remote code execution via unsafe deserialization",
		fix: "Avoid Marshal for untrusted inputs; use JSON and validate schema.",
		fileTypes: [".rb"],
	},
	{
		name: "Ruby SSRF via URI.open/open-uri with request-derived URL",
		regex: /\b(URI\.open|OpenURI\.open_uri)\(\s*(params|request\.params|cookies|session)\b/g,
		severity: "high",
		message:
			"Fetching a URL from request-derived input can enable SSRF to internal services/metadata endpoints",
		fix: "Whitelist allowed hosts/schemes; block private IPs and link-local ranges.",
		fileTypes: [".rb"],
	},
	{
		name: "Ruby SSRF via Net::HTTP + URI(params)",
		regex: /Net::HTTP\.(get|get_response|start)\s*\(\s*URI\(\s*(params|request\.params)\b/g,
		severity: "high",
		message: "Net::HTTP requests built from request-derived URLs can enable SSRF",
		fix: "Whitelist allowed hosts/schemes; block private IPs and link-local ranges.",
		fileTypes: [".rb"],
	},
	{
		name: "Ruby open redirect",
		regex: /\bredirect_to\s*\(?\s*(params|request\.params|request\.(referer|referrer))\b/g,
		severity: "medium",
		message: "Redirecting to request-derived URLs can enable open redirect attacks",
		fix: "Validate redirect targets; restrict to same-host paths or allowlisted hosts.",
		fileTypes: [".rb"],
	},
	{
		name: "Ruby path traversal / arbitrary file access from params",
		regex:
			/\b(send_file|File\.(read|open)|IO\.read)\(\s*(params|request\.params|cookies|session)\b/g,
		severity: "high",
		message:
			"File operations using request-derived paths can enable path traversal and arbitrary file read/write",
		fix: "Never use user-provided paths directly; use IDs, canonicalize paths, and enforce a base directory.",
		fileTypes: [".rb"],
	},
	{
		name: "Ruby open() command injection",
		regex: /\bopen\s*\(\s*["']\||\bopen\s*\([^)]*#\{[^}]*\}/g,
		severity: "critical",
		message: "Ruby open() with pipe or interpolation allows command execution",
		fix: "Use File.open for files; avoid pipe syntax with user input",
		fileTypes: [".rb"],
	},
	{
		name: "Ruby mass assignment",
		regex: /attr_accessible|attr_protected|permit!|params\.(permit|require)\s*\([^)]*\)/g,
		severity: "medium",
		message: "Check mass assignment protection is correctly configured",
		fix: "Use strong parameters; whitelist only needed attributes",
		fileTypes: [".rb"],
	},
]);
