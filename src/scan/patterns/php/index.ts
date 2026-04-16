import { definePatterns } from "../types.js";

export default definePatterns([
	{
		name: "SSRF via curl/file_get_contents",
		regex: /file_get_contents\s*\(\s*\$|curl_setopt\s*\([^)]*CURLOPT_URL[^)]*\$/g,
		severity: "high",
		message: "URL fetching with potentially user-controlled input",
		fix: "Validate and whitelist allowed URL schemes and hosts",
		fileTypes: [".php"],
	},
	{
		name: "Path traversal via include/require",
		regex: /include\s*\(\s*\$|require\s*\(\s*\$|include_once\s*\(\s*\$|require_once\s*\(\s*\$/g,
		severity: "critical",
		message: "PHP include with user-controlled path enables LFI/RFI",
		fix: "Use whitelist of allowed files, never include user input directly",
		fileTypes: [".php"],
	},
	{
		name: "Unrestricted file upload (PHP)",
		regex: /move_uploaded_file\s*\(/g,
		severity: "high",
		message: "File upload without visible type validation may allow malicious uploads",
		fix: "Validate file extension, MIME type, and content; store outside webroot",
		fileTypes: [".php"],
	},
	{
		name: "Command injection via exec/system/passthru/shell_exec",
		regex: /(?:exec|system|passthru|shell_exec)\s*\(\s*\$|`[^`]*\$\w+/g,
		severity: "critical",
		message: "Process execution with potentially user-controlled input enables command injection",
		fix: "Use exec() with explicit argument arrays, validate/whitelist all inputs, or use safer alternatives",
		fileTypes: [".php"],
	},
	{
		name: "preg_replace() with /e modifier (RCE)",
		regex: /preg_replace\s*\(\s*['"][^'"]*\/e[gimsxADSUXJu]*['"]/g,
		severity: "critical",
		message: "preg_replace() /e modifier executes replacement as PHP code - deprecated RCE vector",
		fix: "Replace with preg_replace_callback() - the /e modifier was removed in PHP 7.0",
		fileTypes: [".php"],
	},
	{
		name: "unserialize() on user input (RCE)",
		regex:
			/unserialize\s*\(\s*\$|unserialize\s*\([^)]*\+|unserialize\s*\(\s*$_(GET|POST|REQUEST|COOKIE)/g,
		severity: "critical",
		message: "PHP unserialize() on user-controlled input enables remote code execution",
		fix: "Never unserialize untrusted data; use JSON or other safe serialization formats",
		fileTypes: [".php"],
	},
	{
		name: "extract() on superglobals (variable injection)",
		regex: /extract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|ENV|SERVER)/g,
		severity: "high",
		message: "extract() on superglobals enables variable injection attacks",
		fix: "Access superglobal variables directly instead of using extract()",
		fileTypes: [".php"],
	},
	{
		name: "CRLF header injection via header()",
		regex: /header\s*\([^)]*\$|header\s*\([^)]*\+|header\s*\(\s*$_(GET|POST|REQUEST|COOKIE)/g,
		severity: "high",
		message:
			"header() with user-controlled input enables HTTP response header injection (CRLF injection)",
		fix: "Never pass user input to header(); validate and sanitize all header values",
		fileTypes: [".php"],
	},
	{
		name: "SQL string concatenation (mysql_query/mysqli_query)",
		regex: /(?:mysql|mysqli)_query\s*\([^)]*\+|mysql_query\s*\([^)]*\$|mysqli_query\s*\([^)]*\$/g,
		severity: "critical",
		message: "SQL query with string concatenation is vulnerable to SQL injection",
		fix: "Use prepared statements with parameterized queries instead of string concatenation",
		fileTypes: [".php"],
	},
]);
