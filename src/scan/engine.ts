import { ansi } from "../ansi.js";
import { validateAgentChain } from "./agent-chain-validator.js";
import type { RedwoodConfig } from "./config.js";
import { scanDependencies } from "./deps.js";
import { getDiffInfo, isLineChanged, type DiffInfo } from "./git.js";
import { scanMCP } from "./mcp.js";
import { scanPatterns } from "./patterns.js";
import { scanSecrets } from "./secrets.js";

export interface Issue {
	id: string;
	type: string;
	severity: "critical" | "high" | "medium" | "low";
	confidence?: "high" | "medium" | "low";
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
	/** Git base ref for diff mode — only scan changed files */
	diffBase?: string;
	/** Only flag findings on changed lines (requires diffBase) */
	newOnly?: boolean;
	/** Minimum confidence level to include in results */
	minConfidence?: "high" | "medium" | "low";
}

export async function scan(repoPath: string, options: ScanOptions = {}): Promise<Issue[]> {
	// Generate unique IDs for each issue
	let idCounter = 0;
	const generateId = () => `issue-${Date.now()}-${idCounter++}`;

	// Resolve diff info if diff mode requested
	let diffInfo: DiffInfo | null = null;
	if (options.diffBase) {
		if (!options.quiet) {
			console.log(ansi.dim(`  📂 Diff mode: comparing against ${options.diffBase}...`));
		}
		diffInfo = getDiffInfo(repoPath, options.diffBase);
		if (!options.quiet) {
			console.log(ansi.dim(`  📂 Changed files: ${diffInfo.changedFiles.size}`));
		}
	}

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
		scanners.push(["Secrets", () => scanSecrets(repoPath, diffInfo?.changedFiles)]);
	}
	if (config.scanners?.dependencies !== false) {
		scanners.push(["Dependencies", () => scanDependencies(repoPath)]);
	}
	if (config.scanners?.patterns !== false) {
		scanners.push(["Patterns", () => scanPatterns(repoPath, options.bypassIgnore, diffInfo?.changedFiles)]);
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

	// Apply confidence scoring
	applyConfidence(deduped);

	// Filter by changed lines if --new-only
	if (options.newOnly && diffInfo) {
		filterToNewOnly(deduped, diffInfo);
	}

	// Filter by minimum confidence
	if (options.minConfidence) {
		const confidenceLevel: Record<string, number> = { high: 0, medium: 1, low: 2 };
		const minLevel = confidenceLevel[options.minConfidence] ?? 2;
		const filtered = deduped.filter((i) => {
			const level = confidenceLevel[i.confidence ?? "high"] ?? 2;
			return level <= minLevel;
		});
		deduped.length = 0;
		deduped.push(...filtered);
	}

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

/**
 * Apply confidence scoring to issues based on contextual signals.
 *
 * Rules:
 * - high: Pattern matched on its own (the default — most patterns are precise)
 * - medium: Pattern matched but some ambiguity (e.g., generic variable name in sink)
 * - low: Safe context hit, test file, low-entropy secret, or inline ignore present
 */
export function applyConfidence(issues: Issue[]): void {
	const TEST_FILE_PATTERNS = [
		/\.test\.[jt]sx?$/,
		/\.spec\.[jt]sx?$/,
		/__tests__\//,
		/\/tests?\//,
		/\/spec\//,
		/\.test\.py$/,
		/\.test\.rb$/,
		/test_.*\.py$/,
		/.*_test\.go$/,
		/.*_test\.rs$/,
	];

	const SAFE_CONTEXT_MARKERS = [
		"__dirname",
		"__filename",
		"path.join",
		"path.resolve",
		"process.cwd()",
		"fs.readFileSync",
		"fs.writeFileSync",
		"import.meta.url",
		"new URL(",
	];

	for (const issue of issues) {
		// Test files → low confidence
		if (issue.file && TEST_FILE_PATTERNS.some((p) => p.test(issue.file))) {
			issue.confidence = "low";
			continue;
		}

		// Check for safe context in the matched code or message
		const contextText = [issue.match, issue.message].filter(Boolean).join(" ");
		if (SAFE_CONTEXT_MARKERS.some((m) => contextText.includes(m))) {
			issue.confidence = "low";
			continue;
		}

		// Secrets with low entropy hints in the match
		if (issue.match) {
			const valueMatch = issue.match.match(/['"]([^'"]+)['"]/);
			if (valueMatch && valueMatch[1].length < 16) {
				issue.confidence = "low";
				continue;
			}
		}

		// Default: high confidence
		issue.confidence = issue.confidence ?? "high";
	}
}

/**
 * Filter issues to only those on changed lines (for --new-only mode).
 *
 * For deduped issues with locations[], filters the locations array
 * and removes issues with no remaining locations.
 */
function filterToNewOnly(issues: Issue[], diffInfo: DiffInfo): void {
	for (let i = issues.length - 1; i >= 0; i--) {
		const issue = issues[i];

		if (issue.locations) {
			const originalCount = issue.locations.length;

			// Filter locations to only changed lines
			issue.locations = issue.locations.filter((loc) => {
				const hunks = diffInfo.changedHunks.get(loc.file);
				if (!hunks || hunks.length === 0) return false;
				if (!loc.line) return true; // File-level finding — keep if file was changed
				return isLineChanged(loc.line, hunks);
			});

			// Remove issue if no locations remain
			if (issue.locations.length === 0) {
				issues.splice(i, 1);
			} else {
				// Update file count if locations were reduced
				if (issue.locations.length < originalCount && originalCount > 1) {
					issue.file = `(${issue.locations.length} files)`;
				}

				if (issue.locations.length === 1) {
					// Unwrap single location back to file/line
					issue.file = issue.locations[0].file;
					issue.line = issue.locations[0].line;
				}
			}
		} else if (issue.file && issue.line) {
			// Non-deduped issue — check if its line was changed
			const hunks = diffInfo.changedHunks.get(issue.file);
			if (!hunks || !isLineChanged(issue.line, hunks)) {
				issues.splice(i, 1);
			}
		}
	}
}
