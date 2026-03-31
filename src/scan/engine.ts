import chalk from "chalk";
import { validateAgentChain } from "./agent-chain-validator.js";
import type { RedwoodConfig } from "./config.js";
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
	severity?: "critical" | "high" | "medium" | "low";
	config?: RedwoodConfig;
}

export async function scan(repoPath: string, options: ScanOptions = {}): Promise<Issue[]> {
	// Generate unique IDs for each issue
	let idCounter = 0;
	const generateId = () => `issue-${Date.now()}-${idCounter++}`;

	// Use config if provided, otherwise use defaults
	const config = options.config || {
		scanners: {
			secrets: true,
			dependencies: true,
			patterns: true,
			mcp: true,
			agentChain: true,
		},
	};

	// Build scanner promises based on config
	const scanners: [string, () => Promise<Issue[]>][] = [];

	if (config.scanners?.secrets !== false) {
		scanners.push(["Secrets", () => scanSecrets(repoPath)]);
	}
	if (config.scanners?.dependencies !== false) {
		scanners.push(["Dependencies", () => scanDependencies(repoPath)]);
	}
	if (config.scanners?.patterns !== false) {
		scanners.push(["Patterns", () => scanPatterns(repoPath)]);
	}
	if (config.scanners?.mcp !== false) {
		scanners.push(["MCP", () => scanMCP(repoPath)]);
	}

	// Run enabled scanners in parallel
	const scannerResults = await Promise.all(
		scanners.map(([name, scannerFn]) => runScanner(name, scannerFn, options.verbose))
	);

	// Run agent chain validation separately (optional)
	let chainIssues: Issue[] = [];
	if (config.scanners?.agentChain !== false) {
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
	}

	// Combine all issues with IDs
	const allIssues: Issue[] = [
		...scannerResults.flatMap((issues, _index) => issues.map((i) => ({ ...i, id: generateId() }))),
		...chainIssues.map((i) => ({ ...i, id: generateId() })),
	];

	// Apply max findings limit if configured
	if (config.maxFindings && allIssues.length > config.maxFindings) {
		allIssues.length = config.maxFindings;
	}

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
