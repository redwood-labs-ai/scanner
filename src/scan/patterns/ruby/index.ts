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
