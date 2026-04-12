import { ansi } from "../ansi.js";
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
	/** Populated after dedup — all affected locations for this issue type */
	locations?: Array<{ file: string; line?: number }>;
}

export interface ScanOptions {
	verbose?: boolean;
	/** Suppress progress output (for JSON/SARIF modes) */
	quiet?: boolean;
	severity?: "critical" | "high" | "medium" | "low";
	bypassIgnore?: boolean;
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
		scanners.push(["Patterns", () => scanPatterns(repoPath, options.bypassIgnore)]);
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
			console.log(ansi.cyan(`  🔗 Validating agent orchestration chains...`));
		}
		try {
			chainIssues = await validateAgentChain(repoPath, { quiet: options.quiet });
			if (chainIssues.length > 0 && options.verbose) {
				console.log(ansi.dim(`  Chain validation: ${chainIssues.length} issue(s)`));
			}
		} catch (error) {
			if (options.verbose) {
				console.log(ansi.yellow(`  ⚠️  Chain validation skipped: ${error}`));
			}
		}
	}

	// Combine all issues with IDs
	const allIssues: Issue[] = [
		...scannerResults.flatMap((issues, _index) => issues.map((i) => ({ ...i, id: generateId() }))),
		...chainIssues.map((i) => ({ ...i, id: generateId() })),
	];

	// Deduplicate issues by type — collapse per-file findings into one issue with locations[]
	const deduped = deduplicateIssues(allIssues);

	// Apply max findings limit if configured
	if (config.maxFindings && deduped.length > config.maxFindings) {
		deduped.length = config.maxFindings;
	}

	return deduped;
}

/**
 * Deduplicate issues by type.
 *
 * Pattern scanners emit one finding per file match, which creates massive
 * output when a rule like "Prototype pollution via convict" fires across
 * 15 files. This groups by issue.type, keeps the highest severity, and
 * populates a locations[] array with every affected file+line.
 */
function deduplicateIssues(issues: Issue[]): Issue[] {
	const groups = new Map<string, Issue[]>();

	for (const issue of issues) {
		const existing = groups.get(issue.type);
		if (existing) {
			existing.push(issue);
		} else {
			groups.set(issue.type, [issue]);
		}
	}

	const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
	const deduped: Issue[] = [];

	for (const [_type, group] of groups) {
		if (group.length === 1) {
			// Single occurrence — add locations array for consistency
			const issue = group[0];
			issue.locations = [{ file: issue.file, line: issue.line }];
			deduped.push(issue);
			continue;
		}

		// Multiple occurrences — pick representative with highest severity
		group.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));
		const representative = group[0];

		deduped.push({
			...representative,
			file: `(${group.length} files)`,
			line: undefined,
			locations: group.map((i) => ({ file: i.file, line: i.line })),
		});
	}

	// Sort by severity
	deduped.sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

	return deduped;
}

async function runScanner(
	name: string,
	scanner: () => Promise<Issue[]>,
	verbose?: boolean
): Promise<Issue[]> {
	if (verbose) {
		console.log(ansi.dim(`  Scanning: ${name}...`));
	}

	try {
		const issues = await scanner();
		if (verbose && issues.length > 0) {
			console.log(ansi.dim(`  ${name}: ${issues.length} issue(s)`));
		}
		return issues;
	} catch (error) {
		if (verbose) {
			console.log(ansi.red(`  ${name}: error - ${error}`));
		}
		return [];
	}
}
