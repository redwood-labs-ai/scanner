import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { Issue } from "./engine.js";
import { DEFAULT_IGNORE_DIRS, isIgnored, loadRedwoodIgnore, shouldSkipDir } from "./ignore.js";

/**
 * MCP-specific security scanner
 *
 * Checks for common security issues in Model Context Protocol servers:
 * - Overly permissive tool definitions
 * - Filesystem access without restrictions
 * - Shell execution capabilities
 * - Prompt injection vectors in tool descriptions
 * - Missing permission boundaries
 */

export async function scanMCP(repoPath: string): Promise<Issue[]> {
	const issues: Issue[] = [];

	// Look for MCP server indicators
	const mcpFiles = await findMCPFiles(repoPath);

	if (mcpFiles.length === 0) {
		return issues; // Not an MCP project
	}

	// Load .redwoodignore patterns
	const ignoreConfig = await loadRedwoodIgnore(repoPath);
	const ignorePatterns = ignoreConfig?.patterns || [];

	for (const file of mcpFiles) {
		// Skip if file matches .redwoodignore patterns
		if (isIgnored(file, repoPath, ignorePatterns)) {
			continue;
		}

		const relPath = relative(repoPath, file);
		const content = readFileSync(file, "utf-8");

		// Check for filesystem access
		const fsIssues = checkFilesystemAccess(content, relPath);
		issues.push(...fsIssues);

		// Check for shell execution
		const shellIssues = checkShellExecution(content, relPath);
		issues.push(...shellIssues);

		// Check for overly broad tool definitions
		const toolIssues = checkToolDefinitions(content, relPath);
		issues.push(...toolIssues);

		// Check for prompt injection vectors
		const injectionIssues = checkPromptInjection(content, relPath);
		issues.push(...injectionIssues);
	}

	return issues;
}

async function findMCPFiles(repoPath: string): Promise<string[]> {
	const files: string[] = [];
	const mcpIndicators = [
		"@modelcontextprotocol/sdk",
		"mcp-server",
		"MCPServer",
		"Server.create",
		"tool_definition",
		"ToolDefinition",
	];

	// Load .redwoodignore patterns
	const ignoreConfig = await loadRedwoodIgnore(repoPath);
	const ignorePatterns = ignoreConfig?.patterns || [];

	function searchDir(searchPath: string) {
		try {
			const entries = readdirSync(searchPath);

			for (const entry of entries) {
				// Skip directories based on centralized defaults
				if (DEFAULT_IGNORE_DIRS.includes(entry)) continue;

				const fullPath = join(searchPath, entry);

				// Skip if directory matches .redwoodignore patterns
				if (ignorePatterns.length > 0 && shouldSkipDir(entry, fullPath, repoPath, ignorePatterns))
					continue;

				const stat = statSync(fullPath);

				if (stat.isDirectory()) {
					searchDir(fullPath);
				} else if (stat.isFile() && /\.(js|ts|py)$/.test(entry)) {
					// Skip if file matches .redwoodignore patterns
					if (ignorePatterns.length > 0 && isIgnored(fullPath, repoPath, ignorePatterns)) continue;

					try {
						const content = readFileSync(fullPath, "utf-8");
						if (mcpIndicators.some((indicator) => content.includes(indicator))) {
							files.push(fullPath);
						}
					} catch {}
				}
			}
		} catch {}
	}

	searchDir(repoPath);
	return files;
}

function checkFilesystemAccess(content: string, file: string): Issue[] {
	const issues: Issue[] = [];

	// Check for unrestricted filesystem operations
	const fsPatterns = [
		{ pattern: /readFile\s*\([^)]*\)/g, name: "File read" },
		{ pattern: /writeFile\s*\([^)]*\)/g, name: "File write" },
		{ pattern: /readdir\s*\([^)]*\)/g, name: "Directory listing" },
		{ pattern: /unlink\s*\([^)]*\)/g, name: "File deletion" },
		{ pattern: /rmdir\s*\([^)]*\)/g, name: "Directory deletion" },
		{ pattern: /open\s*\([^)]*,\s*['"]w/g, name: "File write (Python)" },
		{ pattern: /os\.(remove|unlink)\s*\(/g, name: "File deletion (Python)" },
	];

	// Check if there's path validation
	const hasPathValidation =
		content.includes("path.resolve") ||
		content.includes("path.normalize") ||
		content.includes("sanitize") ||
		content.includes("allowlist") ||
		content.includes("whitelist") ||
		content.includes("isAbsolute") ||
		content.includes("startsWith(baseDir") ||
		content.includes("startsWith(allowed");

	for (const { pattern, name } of fsPatterns) {
		if (pattern.test(content) && !hasPathValidation) {
			issues.push({
				id: `mcp-fs-${issues.length + 1}`,
				type: `MCP: Unrestricted ${name}`,
				severity: "high",
				file,
				message: `${name} operation without apparent path validation`,
				fix: "Add path validation to restrict filesystem access to allowed directories",
			});
		}
	}

	return issues;
}

function checkShellExecution(content: string, file: string): Issue[] {
	const issues: Issue[] = [];

	const _shellPatterns = [
		/exec\s*\(/g,
		/execSync\s*\(/g,
		/spawn\s*\(/g,
		/spawnSync\s*\(/g,
		/child_process/g,
		/subprocess\.(run|call|Popen)/g,
		/os\.system\s*\(/g,
	];

	// Check if shell is exposed as a tool
	const hasShellTool =
		content.includes("shell") &&
		(content.includes("tool") || content.includes("Tool")) &&
		(content.includes("execute") || content.includes("run") || content.includes("command"));

	if (hasShellTool) {
		issues.push({
			id: "mcp-shell-tool",
			type: "MCP: Shell Execution Tool",
			severity: "critical",
			file,
			message: "MCP server exposes shell execution as a tool - this is extremely dangerous",
			fix: "Remove shell execution capability or heavily restrict allowed commands",
		});
	}

	return issues;
}

function checkToolDefinitions(content: string, file: string): Issue[] {
	const issues: Issue[] = [];

	// Look for tool definitions with concerning descriptions
	const toolDefPattern = /(?:name|tool_name|toolName)\s*[:=]\s*['"]([^'"]+)['"]/g;
	// Tool names that are dangerous as standalone names
	const dangerousExact = new Set(["exec", "shell", "eval", "sudo", "su", "rm"]);

	// Tool name stems that are dangerous when they start a compound name
	// (e.g., "exec_command", "shell_run", "run_arbitrary")
	const dangerousPrefixes = ["exec_", "shell_", "eval_", "run_command", "run_arbitrary"];

	let match;
	while ((match = toolDefPattern.exec(content)) !== null) {
		const toolName = match[1].toLowerCase();
		if (
			dangerousExact.has(toolName) ||
			dangerousPrefixes.some((prefix) => toolName.startsWith(prefix))
		) {
			issues.push({
				id: `mcp-tool-${toolName}`,
				type: "MCP: Dangerous Tool Name",
				severity: "medium",
				file,
				message: `Tool "${match[1]}" has a name suggesting dangerous capabilities`,
				fix: "Ensure this tool has proper authorization and input validation",
			});
		}
	}

	return issues;
}

function checkPromptInjection(content: string, file: string): Issue[] {
	const issues: Issue[] = [];

	// Check for user input being directly used in tool descriptions
	const injectionPatterns = [
		/description\s*[:=]\s*[`'"].*\$\{/g, // Template literal injection
		/description\s*[:=]\s*.*\+\s*user/gi, // String concat with user input
		/description\s*[:=]\s*f['"].*\{.*input/gi, // Python f-string with input
	];

	for (const pattern of injectionPatterns) {
		if (pattern.test(content)) {
			issues.push({
				id: `mcp-injection-${issues.length + 1}`,
				type: "MCP: Potential Prompt Injection",
				severity: "high",
				file,
				message: "Dynamic content in tool description could allow prompt injection",
				fix: "Use static tool descriptions and validate/sanitize any dynamic content",
			});
		}
	}

	return issues;
}
