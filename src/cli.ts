#!/usr/bin/env node

/**
 * Redwood Scanner CLI
 * Security scanner for AI-native codebases
 */

import { parseArgs } from "node:util";
import { ansi } from "./ansi.js";
import { generatePrompt } from "./prompt.js";
import { validateAgentChain } from "./scan/agent-chain-validator.js";
import { loadConfig, loadConfigFromPath } from "./scan/config.js";
import { type Issue, scan } from "./scan/engine.js";

const VERSION = "0.4.2";

// Helper functions

function getSeverityLevel(severity: string): number {
	const levels: Record<string, number> = {
		critical: 0,
		high: 1,
		medium: 2,
		low: 3,
		info: 4,
	};
	return levels[severity] ?? 5;
}

function meetsSeverityThreshold(issueSeverity: string, threshold: string | undefined): boolean {
	if (!threshold) return issueSeverity === "critical"; // Default behavior

	const issueLevel = getSeverityLevel(issueSeverity);
	const thresholdLevel = getSeverityLevel(threshold);

	return issueLevel <= thresholdLevel;
}

function getSeverityIcon(severity: string): string {
	const icons: Record<string, string> = {
		critical: "🔴",
		high: "🟠",
		medium: "🟡",
		low: "🟢",
		info: "⚪",
	};
	return icons[severity] || "⚪";
}

function getConfidenceIcon(confidence: string | undefined): string {
	const icons: Record<string, string> = {
		high: "🎯",
		medium: "❓",
		low: "💭",
	};
	return icons[confidence ?? "high"] || "🎯";
}

function printResults(issues: Issue[]) {
	if (issues.length === 0) {
		console.log(ansi.green("\n✅ No security issues found\n"));
		return;
	}

	console.log(`\n${"─".repeat(50)}`);
	console.log(ansi.bold(`Found ${issues.length} issue(s):`));
	console.log("─".repeat(50));

	for (const issue of issues) {
		const sev = issue.severity;
		const icon = getSeverityIcon(sev);
		const confIcon = getConfidenceIcon(issue.confidence);
		const locs = issue.locations || [{ file: issue.file, line: issue.line }];

		console.log(
			`\n${icon} ${ansi.bold(issue.type)}${locs.length > 1 ? ` (${locs.length} files)` : ""} ${confIcon} ${issue.confidence ?? "high"}`
		);
		console.log(ansi.dim(`   ${issue.message}`));
		if (issue.fix) {
			console.log(ansi.cyan(`   Fix: ${issue.fix.split("\n")[0]}`));
		}
		console.log("   Files:");

		const maxFiles = 5;
		locs.slice(0, maxFiles).forEach((loc) => {
			const locStr = loc.line ? `${loc.file}:${loc.line}` : loc.file;
			console.log(ansi.dim(`   - ${locStr}`));
		});
		if (locs.length > maxFiles) {
			console.log(ansi.dim(`   ... and ${locs.length - maxFiles} more`));
		}
	}

	// Summary
	console.log(`\n${"─".repeat(50)}`);
	console.log(ansi.bold("Summary"));
	console.log("─".repeat(50));

	const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
	issues.forEach((i) => bySev[i.severity as keyof typeof bySev]++);

	if (bySev.critical) console.log(`${getSeverityIcon("critical")} Critical: ${bySev.critical}`);
	if (bySev.high) console.log(`${getSeverityIcon("high")} High: ${bySev.high}`);
	if (bySev.medium) console.log(`${getSeverityIcon("medium")} Medium: ${bySev.medium}`);
	if (bySev.low) console.log(`${getSeverityIcon("low")} Low: ${bySev.low}`);
	console.log();
}

function toSarif(issues: Issue[], _repoPath: string) {
	// Expand deduplicated issues back into individual results per location
	const results: any[] = [];
	for (const issue of issues) {
		const locs = issue.locations || [{ file: issue.file, line: issue.line }];
		for (const loc of locs) {
			results.push({
				ruleId: issue.type,
				level:
					issue.severity === "critical" ? "error" : issue.severity === "high" ? "error" : "warning",
				message: { text: issue.message },
				locations: [
					{
						physicalLocation: {
							artifactLocation: { uri: loc.file },
							region: { startLine: loc.line || 1 },
						},
					},
				],
			});
		}
	}

	return {
		$schema:
			"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		version: "2.1.0",
		runs: [
			{
				tool: {
					driver: {
						name: "redwood-scanner",
						version: VERSION,
						informationUri: "https://github.com/redwood-labs/scanner",
					},
				},
				results,
			},
		],
	};
}

function printHelp(command?: string) {
	if (command === "scan") {
		console.log(`
${ansi.bold("redwood scan")} <path> [options]

${ansi.bold("Description:")}
  Run security scan on a repository

${ansi.bold("Positional:")}
  <path>    Path to repository

${ansi.bold("Options:")}
  --config <path>    Path to .redwoodrc file
  --json             Output results as JSON
  --sarif            Output results in SARIF format
  --verbose          Show detailed output
  --bypass-ignore    Critical mode: include bypassed findings as issues
  --severity <level> Minimum severity to fail on (critical|high|medium|low)
  --diff <base>      Only scan files changed vs git ref (e.g., main, origin/main)
  --new-only         Only flag findings on changed lines (requires --diff)
  --confidence <lvl> Minimum confidence to show (high|medium|low)
  --no-prompt        Suppress LLM fix prompt (for CI/scripted use)
  --help             Show this help message
`);
	} else if (command === "agents" || command === "agent-chain") {
		console.log(`
${ansi.bold("redwood agents")} <path> [options]

${ansi.bold("Description:")}
  Validate agent orchestration chains

${ansi.bold("Positional:")}
  <path>    Path to repository

${ansi.bold("Options:")}
  --json       Output results as JSON
  --no-prompt  Suppress LLM fix prompt (for CI/scripted use)
  --help       Show this help message
`);
	} else {
		console.log(`
${ansi.bold("redwood")} [command] [options]

${ansi.bold("Description:")}
  🌲 Security scanner for AI-native codebases

${ansi.bold("Version:")}\n  ${VERSION}

${ansi.bold("Commands:")}
  scan        Run security scan on a repository
  agents      Validate agent orchestration chains

${ansi.bold("Options:")}
  --help     Show this help message
  --version  Show version number
`);
	}
}

async function runScan(
	repoPath: string,
	options: Record<string, string | boolean | (string | boolean)[] | undefined>
) {
	try {
		// Load config if specified, otherwise search for it
		let config = await loadConfig(repoPath);

		const configVal = options.config;
		if (typeof configVal === "string") {
			// User specified a custom config path
			config = await loadConfigFromPath(configVal);
		}

		// CLI options override config file
		const verboseVal = options.verbose;
		const verbose = verboseVal === true;
		if (verboseVal !== undefined) config.output = { ...config.output, verbose };

		const severityVal = options.severity;
		if (typeof severityVal === "string") config.severity = severityVal as any;

		const jsonVal = options.json;
		if (jsonVal === true) config.output = { ...config.output, json: true };

		const sarifVal = options.sarif;
		if (sarifVal === true) config.output = { ...config.output, sarif: true };

		if (verbose) {
			console.log(ansi.dim(`Scanning ${repoPath}...`));
		}

		const bypassIgnore = options["bypass-ignore"] === true;

		// Diff mode options
		const diffBase = typeof options.diff === "string" ? options.diff : undefined;
		const newOnly = options["new-only"] === true;
		if (newOnly && !diffBase) {
			console.error(ansi.red("Error: --new-only requires --diff <base>"));
			process.exit(1);
		}

		// Confidence filter
		const confidenceVal = options.confidence;
		const minConfidence =
			typeof confidenceVal === "string"
				? (confidenceVal as "high" | "medium" | "low")
				: undefined;

		// Determine output format early (needed for quiet mode)
		const useJson = jsonVal === true || config.output?.json;
		const useSarif = sarifVal === true || config.output?.sarif;

		const issues = await scan(repoPath, {
			verbose,
			quiet: useJson || useSarif, // Suppress progress output for machine-readable formats
			severity: (typeof severityVal === "string"
				? severityVal
				: config.severity === "info"
					? "low"
					: config.severity) as "critical" | "high" | "medium" | "low" | undefined,
			bypassIgnore,
			config,
			diffBase,
			newOnly,
			minConfidence,
		});
		const effectiveSeverity =
			typeof severityVal === "string" ? severityVal : config.severity || "critical";

		if (useJson) {
			console.log(JSON.stringify(issues, null, 2));
			const shouldFail = issues.some((i) => meetsSeverityThreshold(i.severity, effectiveSeverity));
			process.exit(shouldFail ? 1 : 0);
		}

		if (useSarif) {
			console.log(JSON.stringify(toSarif(issues, repoPath), null, 2));
			const shouldFail = issues.some((i) => meetsSeverityThreshold(i.severity, effectiveSeverity));
			process.exit(shouldFail ? 1 : 0);
		}

		printResults(issues);

		// Generate LLM prompt (on by default, suppressed with --no-prompt)
		const showPrompt = options["no-prompt"] !== true;
		if (showPrompt && issues.length > 0) {
			const prompt = generatePrompt(issues);
			if (prompt) {
				console.log("─".repeat(50));
				console.log(ansi.bold("📋 Copy for your AI assistant:"));
				console.log("─".repeat(50));
				console.log("");
				console.log(prompt);
			}
		}

		// Exit with error if issues meet severity threshold
		const shouldFail = issues.some((i) => meetsSeverityThreshold(i.severity, effectiveSeverity));
		if (shouldFail) {
			process.exit(1);
		}
	} catch (error: any) {
		console.error(ansi.red("Error:"), error.message);
		process.exit(1);
	}
}

async function runAgents(
	repoPath: string,
	options: Record<string, string | boolean | (string | boolean)[] | undefined>
) {
	try {
		const useJson = options.json === true;

		if (!useJson) {
			console.log(ansi.dim("Analyzing agent orchestration..."));
		}

		const issues = await validateAgentChain(repoPath, { quiet: useJson });

		if (useJson) {
			console.log(JSON.stringify(issues, null, 2));
		} else {
			printResults(issues);

			// Generate LLM prompt (on by default, suppressed with --no-prompt)
			const showPrompt = options["no-prompt"] !== true;
			if (showPrompt && issues.length > 0) {
				const prompt = generatePrompt(issues);
				if (prompt) {
					console.log("─".repeat(50));
					console.log(ansi.bold("📋 Copy for your AI assistant:"));
					console.log("─".repeat(50));
					console.log("");
					console.log(prompt);
				}
			}
		}

		if (issues.some((i) => i.severity === "critical")) {
			process.exit(1);
		}
	} catch (error: any) {
		console.error(ansi.red("Error:"), error.message);
		process.exit(1);
	}
}

async function main() {
	const args = process.argv.slice(2);

	// Handle --version and --help at top level (only if first arg)
	if (args[0] === "--version" || args[0] === "-v") {
		console.log(VERSION);
		process.exit(0);
	}

	if (args[0] === "--help" || args[0] === "-h") {
		printHelp();
		process.exit(0);
	}

	if (args.length === 0) {
		printHelp();
		process.exit(1);
	}

	const command = args[0];

	if (command === "scan" || command === "agents" || command === "agent-chain") {
		// Parse command-specific args
		const parseOptions: any =
			command === "scan"
				? {
						args: args.slice(1),
						allowPositionals: true,
					options: {
						config: { type: "string" },
						json: { type: "boolean" },
						sarif: { type: "boolean" },
						verbose: { type: "boolean" },
						"bypass-ignore": { type: "boolean" },
						severity: { type: "string" },
						diff: { type: "string" },
						"new-only": { type: "boolean" },
						confidence: { type: "string" },
						"no-prompt": { type: "boolean" },
						help: { type: "boolean" },
					},
					}
				: {
						args: args.slice(1),
						allowPositionals: true,
						options: {
							json: { type: "boolean" },
							"no-prompt": { type: "boolean" },
							help: { type: "boolean" },
						},
					};

		// Check for --help on command
		if (parseOptions.args.includes("--help") || parseOptions.args.includes("-h")) {
			printHelp(command);
			process.exit(0);
		}

		const result = parseArgs(parseOptions);
		const options = result.values;

		// Get positional argument (path)
		const repoPath = result.positionals[0];

		if (!repoPath) {
			console.error(ansi.red("Error: Missing required path argument"));
			printHelp(command);
			process.exit(1);
		}

		if (command === "scan") {
			await runScan(repoPath, options);
		} else {
			await runAgents(repoPath, options);
		}
	} else if (command === "--help" || command === "-h") {
		printHelp();
		process.exit(0);
	} else if (command === "--version" || command === "-v") {
		console.log(VERSION);
		process.exit(0);
	} else {
		console.error(ansi.red(`Unknown command: ${command}`));
		printHelp();
		process.exit(1);
	}
}

main();
