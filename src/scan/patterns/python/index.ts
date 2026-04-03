import { definePatterns } from "../types.js";

export default definePatterns([
	{
		name: "SQL f-string injection",
		regex: /f["'][\s\S]{0,20}(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)[\s\S]{0,50}\{/gi,
		severity: "critical",
		message: "SQL query built with f-string is vulnerable to injection",
		fix: "Use parameterized queries with ? or %s placeholders",
		fileTypes: [".py"],
	},
	{
		name: "SQL format string injection",
		regex: /["'][\s\S]{0,20}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,50}["']\.format\s*\(/gi,
		severity: "critical",
		message: "SQL query built with .format() is vulnerable to injection",
		fix: "Use parameterized queries with ? or %s placeholders",
		fileTypes: [".py"],
	},
	{
		name: "SSTI via render_template_string",
		regex: /render_template_string\s*\(/g,
		severity: "high",
		message: "render_template_string is dangerous - ensure no user input reaches it",
		fix: "Use render_template with static template files instead",
		fileTypes: [".py"],
	},
	{
		name: "SSTI via Jinja2 from_string",
		regex: /\.from_string\s*\(/g,
		severity: "high",
		message: "Jinja2 from_string is dangerous - ensure no user input reaches it",
		fix: "Use static templates loaded from files instead",
		fileTypes: [".py"],
	},
	{
		name: "SSTI via Template() direct",
		regex: /\bTemplate\s*\(\s*[^"'][^)]/g,
		severity: "high",
		message: "Template() with variable input may be vulnerable to SSTI",
		fix: "Use static templates; never pass user input to Template constructor",
		fileTypes: [".py"],
	},
	{
		name: "Insecure deserialization (pickle)",
		regex: /pickle\.loads?\s*\(|yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader|yaml\.unsafe_load/g,
		severity: "critical",
		message: "Deserializing untrusted data can lead to remote code execution",
		fix: "Use yaml.safe_load() or json instead of pickle/unsafe yaml",
		fileTypes: [".py"],
	},
	{
		name: "Command injection via os/subprocess",
		regex:
			/os\.system\s*\(|os\.popen\s*\(|subprocess\.call\s*\([^)]*shell\s*=\s*True|subprocess\.Popen\s*\([^)]*shell\s*=\s*True/g,
		severity: "critical",
		message: "Shell command execution with potential user input",
		fix: "Use subprocess with shell=False and pass args as list",
		fileTypes: [".py"],
	},
	{
		name: "SSRF via urllib",
		regex: /urllib\.request\.urlopen\s*\(|urllib2\.urlopen\s*\(|urllib\.urlopen\s*\(/g,
		severity: "high",
		message: "URL fetching function may be vulnerable to SSRF if URL is user-controlled",
		fix: "Validate and whitelist allowed URL schemes and hosts",
		fileTypes: [".py"],
	},
	{
		name: "SSRF via requests library",
		regex:
			/requests\.(get|post|put|delete|head|patch)\s*\([^)]*\+|requests\.(get|post|put|delete|head|patch)\s*\(.*\{/g,
		severity: "high",
		message: "HTTP request with potentially user-controlled URL",
		fix: "Validate and whitelist allowed URL schemes and hosts",
		fileTypes: [".py"],
	},
	{
		name: "Path traversal via open()",
		regex: /open\s*\([^)]*\+|open\s*\(.*\{|open\s*\(\s*f["']/g,
		severity: "high",
		message: "File open with potentially user-controlled path",
		fix: "Use os.path.basename() or validate path does not contain ..",
		fileTypes: [".py"],
	},
	{
		name: "XXE via XML parsing",
		regex:
			/XMLParser\s*\(|xml\.etree\.ElementTree\.parse|lxml\.etree\.parse|xml\.dom\.minidom\.parse/g,
		severity: "high",
		message: "XML parsing may be vulnerable to XXE if external entities not disabled",
		fix: "Disable external entity processing in XML parser",
		fileTypes: [".py"],
	},
	{
		name: "Command injection via webbrowser.open (CVE-2026-4519)",
		regex: /webbrowser\.open\s*\(|webbrowser\.get\.open\s*\(|webbrowser\.control\s*\(/g,
		severity: "high",
		message:
			"webbrowser.open() with user-controlled URLs is vulnerable to command injection. URLs starting with dashes can be interpreted as command-line options to the browser",
		fix: "Validate URLs before passing to webbrowser.open(). Reject URLs starting with dashes. Ensure URL has valid http/https scheme. Consider using a safer alternative for opening URLs",
		fileTypes: [".py"],
	},
]);
