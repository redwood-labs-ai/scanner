/**
 * Agent Chain Validation Scanner
 *
 * Validates the entire agent orchestration graph, not just entry/exit points.
 * Detects vulnerabilities in handoff patterns, context propagation, tool chains,
 * and circular dependencies between agents.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Issue } from "./engine.js";
import { DEFAULT_IGNORE_DIRS, loadRedwoodIgnore, shouldSkipDir } from "./ignore.js";

export interface AgentNode {
	name: string;
	file: string;
	tools: string[];
	handlers: string[];
	dependencies: string[];
}

export interface Edge {
	from: string;
	to: string;
	type: "call" | "context-pass" | "tool-invocation" | "sequence";
	direction: "forward" | "backward" | "bidirectional";
}

export interface ValidationResult {
	node?: AgentNode;
	edge?: Edge;
	message: string;
	severity: "critical" | "high" | "medium" | "low";
	fix?: string;
}

/**
 * Build an orchestration graph from code analysis
 */
async function buildOrchestrationGraph(repoPath: string) {
	const nodes: AgentNode[] = [];
	const edges: Edge[] = [];

	// Find all agent/orchestrator files
	const agentFiles = await findAgentFiles(repoPath);

	for (const file of agentFiles) {
		try {
			const content = readFileSync(file, "utf-8");
			const node = analyzeAgentFile(content, file);
			if (node) nodes.push(node);

			// Find calls between agents in this file
			const localEdges = findLocalCalls(content, file);
			edges.push(...localEdges);
		} catch {}
	}

	return { nodes, edges };
}

/**
 * Find files that appear to be agent/orchestrator implementations
 */
async function findAgentFiles(repoPath: string): Promise<string[]> {
	const files: string[] = [];
	const agentIndicators = [
		"@langchain",
		"agent",
		"orchestration",
		"workflow",
		"Chain",
		"AgentExecutor",
		"LCEL",
		"RunnableSequence",
		"RunnableParallel",
		"mcp-server",
		"createReactHooksAgent",
		"AgentType",
	];

	// Load .redwoodignore patterns
	const ignoreConfig = await loadRedwoodIgnore(repoPath);
	const ignorePatterns = ignoreConfig?.patterns || [];

	function searchDir(searchPath: string): void {
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
				} else if (
					(entry.endsWith(".ts") || entry.endsWith(".js")) &&
					!entry.includes("node_modules")
				) {
					try {
						const content = readFileSync(fullPath, "utf-8");
						if (agentIndicators.some((indicator) => content.includes(indicator))) {
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

/**
 * Analyze a single agent file to extract its structure
 */
function analyzeAgentFile(content: string, file: string): AgentNode | null {
	const name = extractAgentName(content, file);
	if (!name) return null;

	// Extract tool definitions
	const tools = extractTools(content);

	// Extract handler patterns
	const handlers = extractHandlers(content);

	// Extract dependencies (imports from other agent files)
	const dependencies = extractDependencies(content);

	return {
		name,
		file,
		tools,
		handlers,
		dependencies,
	};
}

function extractAgentName(content: string, file: string): string | null {
	const patterns = [
		/class\s+(\w*Agent\w*)/i,
		/export\s+const\s+(\w*Agent\w*)/,
		/function\s+(\w*Agent\w*)/,
		/\bAgentExecutor\b/i,
		/export.*Agent/,
	];

	for (const pattern of patterns) {
		const match = content.match(pattern);
		if (match) return match[1];
	}

	// Default: use file name without extension
	const fileName = file.split("/").pop()?.split(".")[0] || "agent";
	return fileName;
}

function extractTools(content: string): string[] {
	const tools: string[] = [];

	const toolPatterns = [
		/tools:\s*\[([^\]]*)\]/,
		/\btool\s*[:=]\s*['"]([^'"]+)['"]/g,
		/\.use\(['"`](.*?)['"`]/g,
		/useTools?\s*\(\s*(\w+)/g,
		/tools:\s*(\w+)/g,
	];

	for (const pattern of toolPatterns) {
		try {
			const matches = content.match(pattern);
			if (matches) {
				for (const match of matches) {
					tools.push(cleanToolName(match));
				}
			}
		} catch {}
	}

	return [...new Set(tools)];
}

function cleanToolName(name: string): string {
	return name.trim().replace(/['"`]/g, "").split(" ").slice(0, 2).join("_");
}

function extractHandlers(content: string): string[] {
	const handlers: string[] = [];

	const handlerPatterns = [
		/onChainEnd\s*\(/,
		/handleResponse\s*\(/,
		/processOutput\s*\(/,
		/\.then\s*\(\s*async\s+(\w+)/,
		/\.then\s*\((\w+)/,
		/catch\s*\((\w+)/,
		/finally\s*\((\w+)/,
	];

	for (const pattern of handlerPatterns) {
		try {
			const matches = content.match(pattern);
			if (matches) {
				for (const match of matches) {
					handlers.push(cleanHandlerName(match));
				}
			}
		} catch {}
	}

	return [...new Set(handlers)];
}

function cleanHandlerName(name: string): string {
	return name.trim().split(" ").slice(0, 2).join("_").replace(/['"`]/g, "");
}

function extractDependencies(content: string): string[] {
	const dependencies: string[] = [];

	// Look for imports from agent-related packages
	importPatterns.forEach((pattern) => {
		try {
			const matches = content.match(pattern);
			if (matches) {
				for (const match of matches) {
					const depName = extractPackageName(match);
					if (depName && !dependencies.includes(depName)) {
						dependencies.push(depName);
					}
				}
			}
		} catch {}
	});

	return dependencies;
}

const importPatterns = [
	/from\s+['"]([^'"]*\/agent[^'"]*)['"]/g,
	/import\s+\{[^}]*\}\s+from\s+['"]([^'"]*\/chain[^'"]*)['"]/g,
];

function extractPackageName(match: string): string {
	const parts = match.split("/");
	return parts[parts.length - 1] || "";
}

/**
 * Find calls between agents within a single file
 */
function findLocalCalls(content: string, _sourceFile: string): Edge[] {
	const edges: Edge[] = [];

	// Pattern 1: await agent2(...agent1...) - chained calls
	const chainPattern = /await\s+(\w+)\s*\([^)]*await\s+(\w+)/g;
	let match;
	while ((match = chainPattern.exec(content)) !== null) {
		edges.push({
			from: match[1],
			to: match[2],
			type: "call",
			direction: "forward",
		});
	}

	// Pattern 2: Sequential agent patterns
	const sequencePattern = /new\s+(\w+)\s*\([^)]*await\s+(\w+)/g;
	while ((match = sequencePattern.exec(content)) !== null) {
		edges.push({
			from: match[1],
			to: match[2],
			type: "sequence",
			direction: "forward",
		});
	}

	// Pattern 3: Context passing patterns
	const contextPassPattern = /(\w+)\.chain\((?:[\s\S]*?)?(\w+)/g;
	while ((match = contextPassPattern.exec(content)) !== null) {
		edges.push({
			from: match[1],
			to: match[2],
			type: "context-pass",
			direction: "forward",
		});
	}

	return edges;
}

/**
 * Analyze handoff patterns between agents
 */
function analyzeHandoffs(graph: { nodes: AgentNode[]; edges: Edge[] }): Issue[] {
	const issues: Issue[] = [];

	for (const edge of graph.edges) {
		const sourceNode = graph.nodes.find((n) => n.name === edge.from);

		if (!sourceNode) continue;

		// Check if there's validation at handoff points
		const missingValidation = checkHandoffValidation(sourceNode, edge.type);
		issues.push(...missingValidation);
	}

	return issues;
}

function checkHandoffValidation(node: AgentNode, type: string): Issue[] {
	const issues: Issue[] = [];

	switch (type) {
		case "call":
			if (
				!node.handlers.includes("validate") &&
				!node.handlers.includes("sanitize") &&
				!node.handlers.includes("check")
			) {
				issues.push({
					id: `chain-handoff-${Date.now()}-1`,
					type: "Chain Handoff Without Validation",
					severity: "high",
					file: node.file,
					message: `${node.name} appears to call downstream agents without explicit validation/sanitization of responses`,
					fix: "Add output validation handlers that sanitize and verify upstream agent outputs before processing",
				});
			}
			break;

		case "context-pass":
			if (
				node.tools.some(
					(t) => t.toLowerCase().includes("secret") || t.toLowerCase().includes("credential")
				)
			) {
				issues.push({
					id: `chain-context-${Date.now()}-1`,
					type: "Context Contamination Risk",
					severity: "critical",
					file: node.file,
					message: `${node.name} passes context containing sensitive tools without isolation boundaries`,
					fix: "Implement context scoping to prevent sensitive data from propagating to downstream agents",
				});
			}
			break;
	}

	return issues;
}

/**
 * Validate tool definitions within chain context
 */
function validateToolsInChain(graph: { nodes: AgentNode[]; edges: Edge[] }): Issue[] {
	const issues: Issue[] = [];

	// Build adjacency list for traversal
	const adjList: Record<string, string[]> = {};
	for (const edge of graph.edges) {
		if (!adjList[edge.from]) adjList[edge.from] = [];
		adjList[edge.from].push(edge.to);
	}

	// Check each agent's tools in chain context
	for (const node of graph.nodes) {
		const toolIssues = checkToolAuthorization(node, adjList);
		issues.push(...toolIssues);

		// Check for privilege escalation patterns
		const escalationIssues = detectPrivilegeEscalation(node, adjList);
		issues.push(...escalationIssues);
	}

	return issues;
}

function checkToolAuthorization(node: AgentNode, _adjList: Record<string, string[]>): Issue[] {
	const issues: Issue[] = [];

	// Dangerous tool patterns that need extra scrutiny in chains
	const dangerousTools = [
		{ pattern: /exec|shell|cmd/i, name: "Command Execution" },
		{ pattern: /writeFile|fs\.write/i, name: "File Write" },
		{ pattern: /unlink|removeFile/i, name: "File Deletion" },
		{ pattern: /eval|execFunction/i, name: "Code Evaluation" },
	];

	for (const tool of node.tools) {
		for (const dangerous of dangerousTools) {
			if (dangerous.pattern.test(tool)) {
				issues.push({
					id: `chain-tool-${Date.now()}-${tool}`,
					type: "Dangerous Tool in Agent Chain",
					severity: "high",
					file: node.file,
					message: `${node.name} uses ${dangerous.name}: "${tool}" - requires strict authorization checks`,
					fix: "Implement per-invocation authorization and input validation for this tool within the chain",
				});
			}
		}
	}

	return issues;
}

function detectPrivilegeEscalation(node: AgentNode, adjList: Record<string, string[]>): Issue[] {
	const issues: Issue[] = [];

	// Get downstream agents that this node calls
	const downstreamAgents = adjList[node.name] || [];

	if (downstreamAgents.length === 0) return [];

	// Check for escalation patterns
	const hasAdminTools = node.tools.some(
		(t) =>
			t.toLowerCase().includes("admin") ||
			t.toLowerCase().includes("sudo") ||
			t.toLowerCase().includes("root")
	);

	if (hasAdminTools && downstreamAgents.length > 0) {
		issues.push({
			id: `chain-escalation-${Date.now()}`,
			type: "Potential Privilege Escalation in Chain",
			severity: "critical",
			file: node.file,
			message: `${node.name} uses administrative tools but calls ${downstreamAgents.length} other agents - verify downstream authorization is not expanded`,
			fix: "Ensure each agent maintains its own permission boundaries and does not inherit elevated privileges from upstream",
		});
	}

	return issues;
}

/**
 * Detect circular dependencies in the agent graph
 */
function detectCycles(graph: { nodes: AgentNode[]; edges: Edge[] }): Issue[] {
	const issues: Issue[] = [];

	// Build directed adjacency list
	const adjList: Record<string, Set<string>> = {};
	for (const node of graph.nodes) {
		adjList[node.name] = new Set();
	}

	for (const edge of graph.edges) {
		if (!adjList[edge.from]) adjList[edge.from] = new Set();
		adjList[edge.from].add(edge.to);
	}

	// DFS cycle detection
	const visited: Record<string, boolean> = {};
	const recursionStack: Record<string, boolean> = {};

	function hasCycle(nodeName: string): boolean {
		if (recursionStack[nodeName]) return true;
		if (visited[nodeName]) return false;

		visited[nodeName] = true;
		recursionStack[nodeName] = true;

		const neighbors = adjList[nodeName] || [];
		for (const neighbor of neighbors) {
			if (hasCycle(neighbor)) return true;
		}

		delete recursionStack[nodeName];
		return false;
	}

	// Check all nodes
	for (const nodeName of Object.keys(adjList)) {
		if (!visited[nodeName]) {
			if (hasCycle(nodeName)) {
				issues.push({
					id: `chain-cycle-${Date.now()}`,
					type: "Circular Dependency in Agent Chain",
					severity: "high",
					file: "",
					message:
						"Detected circular dependency between agents - risk of infinite loops or resource exhaustion",
					fix: "Break the cycle by introducing intermediate validation steps, timeouts, or explicit termination conditions",
				});
			}
		}
	}

	return issues;
}

/**
 * Audit context propagation across agent boundaries
 */
function auditContextPropagation(graph: { nodes: AgentNode[]; edges: Edge[] }): Issue[] {
	const issues: Issue[] = [];

	// Check for shared mutable state patterns
	const mutabilityPatterns = [/context\.\w+=/, /\[\]\.push\s*\(/, /\.set\s*\(/, /globalThis\./];

	for (const node of graph.nodes) {
		try {
			const content = readFileSync(node.file, "utf-8");

			let hasMutations = false;
			for (const pattern of mutabilityPatterns) {
				if (pattern.test(content)) {
					hasMutations = true;
					break;
				}
			}

			// Check if this node is in a chain
			const hasIncoming = graph.edges.some((e) => e.to === node.name);
			const hasOutgoing = graph.edges.some((e) => e.from === node.name);

			if (hasMutations && hasIncoming && hasOutgoing) {
				issues.push({
					id: `chain-context-${Date.now()}`,
					type: "Context Mutation in Agent Chain",
					severity: "medium",
					file: node.file,
					message: `${node.name} mutates shared context while receiving from upstream and passing to downstream - risk of state leakage`,
					fix: "Use immutable data patterns or explicit context cloning at handoff boundaries",
				});
			}
		} catch {}
	}

	return issues;
}

/**
 * Validate tool invocation chains for security risks
 */
function validateToolChains(graph: { nodes: AgentNode[]; edges: Edge[] }): Issue[] {
	const issues: Issue[] = [];

	// Build a map of tools to their potential data flows
	const toolDataFlows: Record<string, string[]> = {};

	for (const node of graph.nodes) {
		toolDataFlows[node.name] = [...node.tools];
	}

	// Check for dangerous data flow patterns
	for (const edge of graph.edges) {
		const sourceNode = graph.nodes.find((n) => n.name === edge.from);
		if (!sourceNode) continue;

		// If source has sensitive tools, check if destination can access them
		const hasSensitiveTools = sourceNode.tools.some(
			(t) =>
				t.toLowerCase().includes("secret") ||
				t.toLowerCase().includes("credential") ||
				t.toLowerCase().includes("auth")
		);

		if (hasSensitiveTools) {
			const destNode = graph.nodes.find((n) => n.name === edge.to);

			// Check if destination can potentially access sensitive data
			if (destNode && !isIsolatedAgent(destNode, graph.edges)) {
				issues.push({
					id: `chain-dataflow-${Date.now()}`,
					type: "Sensitive Data Flow Risk",
					severity: "high",
					file: sourceNode.file,
					message: `${sourceNode.name} passes data to ${destNode.name} without isolation - sensitive information may leak`,
					fix: "Add explicit data sanitization or use isolated agent instances for downstream processing",
				});
			}
		}
	}

	return issues;
}

function isIsolatedAgent(node: AgentNode, edges: Edge[]): boolean {
	// Agents with no outgoing calls are considered isolated (leaf nodes)
	const hasOutgoing = edges.some((e) => e.from === node.name);
	return !hasOutgoing;
}

/**
 * Main entry point for agent chain validation
 */
export async function validateAgentChain(repoPath: string): Promise<Issue[]> {
	console.log("🔍 Building orchestration graph...");
	const graph = await buildOrchestrationGraph(repoPath);

	if (graph.nodes.length === 0) {
		return [];
	}

	console.log(`   Found ${graph.nodes.length} agent(s)`);

	// Build edge map for node lookups
	const edgeMap: Record<string, Edge[]> = {};
	graph.edges.forEach((edge) => {
		if (!edgeMap[edge.from]) edgeMap[edge.from] = [];
		edgeMap[edge.from].push(edge);
	});

	console.log("🔍 Analyzing handoff patterns...");
	const handoffIssues = analyzeHandoffs(graph);

	console.log("🔍 Validating tool chains...");
	const toolIssues = validateToolsInChain(graph);

	console.log("🔍 Detecting circular dependencies...");
	const cycleIssues = detectCycles(graph);

	console.log("🔍 Auditing context propagation...");
	const contextIssues = auditContextPropagation(graph);

	console.log("🔍 Validating tool data flows...");
	const dataFlowIssues = validateToolChains(graph);

	// Combine all issues with unique IDs
	const allIssues: Issue[] = [
		...handoffIssues.map((i) => ({
			...i,
			id: `chain-${Date.now()}-${i.type.split(" ").join("-")}`,
		})),
		...toolIssues.map((i) => ({
			...i,
			id: `chain-tool-${Date.now()}-${i.type.split(" ").join("-")}`,
		})),
		...cycleIssues.map((i) => ({
			...i,
			id: `chain-cycle-${Date.now()}-${i.type.split(" ").join("-")}`,
		})),
		...contextIssues.map((i) => ({
			...i,
			id: `chain-context-${Date.now()}-${i.type.split(" ").join("-")}`,
		})),
		...dataFlowIssues.map((i) => ({
			...i,
			id: `chain-dataflow-${Date.now()}-${i.type.split(" ").join("-")}`,
		})),
	];

	// Sort by severity
	const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
	allIssues.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

	return allIssues;
}

/**
 * Quick summary of the validation results
 */
export function getChainValidationSummary(issues: Issue[]) {
	const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
	const byType = new Map<string, number>();

	for (const issue of issues) {
		bySeverity[issue.severity]++;
		byType.set(issue.type, (byType.get(issue.type) || 0) + 1);
	}

	return {
		totalIssues: issues.length,
		criticalCount: bySeverity.critical,
		highCount: bySeverity.high,
		mediumCount: bySeverity.medium,
		lowCount: bySeverity.low,
		issueTypes: Object.fromEntries(byType),
	};
}

export default validateAgentChain;
