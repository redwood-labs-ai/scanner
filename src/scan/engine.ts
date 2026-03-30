import chalk from "chalk";
import { validateAgentChain } from "./agent-chain-validator.js";
import { scanDependencies } from "./deps.js";
import { scanMCP } from "./mcp.js";
import { scanPatterns } from "./patterns.js";
import { scanSecrets } from "./secrets.js";

export interface Issue {
	id: string;
	type: string;
	severity: "critical" | "high" | "medium" | "low";
	file: string;
	line?: number;
	message: string;
	match?: string;
	fix?: string;
}

export interface ScanOptions {
	verbose?: boolean;
}

export async function scan(repoPath: string, options: ScanOptions = {}): Promise<Issue[]> {
	// Generate unique IDs for each issue
	let idCounter = 0;
	const generateId = () => `issue-${Date.now()}-${idCounter++}`;

	// Run all scanners in parallel
	const [secrets, deps, patterns, mcp] = await Promise.all([
		runScanner("Secrets", () => scanSecrets(repoPath), options.verbose),
		runScanner("Dependencies", () => scanDependencies(repoPath), options.verbose),
		runScanner("Patterns", () => scanPatterns(repoPath), options.verbose),
		runScanner("MCP", () => scanMCP(repoPath), options.verbose),
	]);

	// Run agent chain validation
	let chainIssues: Issue[] = [];
	if (options.verbose) {
		console.log(chalk.cyan(`  🔗 Validating agent orchestration chains...`));
	}
	try {
		chainIssues = await validateAgentChain(repoPath);
		if (chainIssues.length > 0 && options.verbose) {
			console.log(chalk.dim(`  Chain validation: ${chainIssues.length} issue(s)`));
		}
	} catch (error) {
		if (options.verbose) {
			console.log(chalk.yellow(`  ⚠️ Chain validation skipped: ${error}`));
		}
	}

	// Combine all issues with IDs
	const allIssues = [
		...secrets.map((i) => ({ ...i, id: generateId() })),
		...deps.map((i) => ({ ...i, id: generateId() })),
		...patterns.map((i) => ({ ...i, id: generateId() })),
		...mcp.map((i) => ({ ...i, id: generateId() })),
		...chainIssues.map((i) => ({ ...i, id: generateId() })),
	];

	// Sort by severity
	const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
	allIssues.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

	return allIssues;
}

async function runScanner(
	name: string,
	scanner: () => Promise<Issue[]>,
	verbose?: boolean
): Promise<Issue[]> {
	if (verbose) {
		console.log(chalk.dim(`  Scanning: ${name}...`));
	}

	try {
		const issues = await scanner();
		if (verbose && issues.length > 0) {
			console.log(chalk.dim(`  ${name}: ${issues.length} issue(s)`));
		}
		return issues;
	} catch (error) {
		if (verbose) {
			console.log(chalk.red(`  ${name}: error - ${error}`));
		}
		return [];
	}
}
