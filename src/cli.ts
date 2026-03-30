#!/usr/bin/env node

/**
 * Redwood Scanner CLI
 * Security scanner for AI-native codebases
 */

import chalk from "chalk";
import { Command } from "commander";
import { validateAgentChain } from "./scan/agent-chain-validator.js";
import { type Issue, scan } from "./scan/engine.js";

const program = new Command();

program.name("redwood").description("🌲 Security scanner for AI-native codebases").version("0.1.0");

program
	.command("scan")
	.description("Run security scan on a repository")
	.argument("<path>", "Path to repository")
	.option("--json", "Output results as JSON")
	.option("--sarif", "Output results in SARIF format")
	.option("--verbose", "Show detailed output")
	.action(async (repoPath: string, options) => {
		try {
			if (options.verbose) {
				console.log(chalk.dim(`Scanning ${repoPath}...`));
			}

			const issues = await scan(repoPath, { verbose: options.verbose });

			if (options.json) {
				console.log(JSON.stringify(issues, null, 2));
				process.exit(issues.some((i) => i.severity === "critical") ? 1 : 0);
			}

			if (options.sarif) {
				console.log(JSON.stringify(toSarif(issues, repoPath), null, 2));
				process.exit(issues.some((i) => i.severity === "critical") ? 1 : 0);
			}

			printResults(issues);

			// Exit with error if critical issues found
			if (issues.some((i) => i.severity === "critical")) {
				process.exit(1);
			}
		} catch (error: any) {
			console.error(chalk.red("Error:"), error.message);
			process.exit(1);
		}
	});

program
	.command("agent-chain")
	.description("Validate agent orchestration chains")
	.argument("<path>", "Path to repository")
	.option("--json", "Output results as JSON")
	.action(async (repoPath: string, options) => {
		try {
			console.log(chalk.dim("Analyzing agent orchestration..."));
			const issues = await validateAgentChain(repoPath);

			if (options.json) {
				console.log(JSON.stringify(issues, null, 2));
			} else {
				printResults(issues);
			}

			if (issues.some((i) => i.severity === "critical")) {
				process.exit(1);
			}
		} catch (error: any) {
			console.error(chalk.red("Error:"), error.message);
			process.exit(1);
		}
	});

// Helper functions
function printResults(issues: Issue[]) {
	if (issues.length === 0) {
		console.log(chalk.green("\n✅ No security issues found\n"));
		return;
	}

	console.log(`\n${"─".repeat(50)}`);
	console.log(chalk.bold(`Found ${issues.length} issue(s):`));
	console.log("─".repeat(50));

	// Group by type
	const byType: Record<string, Issue[]> = {};
	for (const issue of issues) {
		const key = issue.type;
		if (!byType[key]) byType[key] = [];
		byType[key].push(issue);
	}

	// Sort by severity
	const severityOrder: Record<string, number> = {
		critical: 0,
		high: 1,
		medium: 2,
		low: 3,
		info: 4,
	};
	const sortedTypes = Object.entries(byType).sort((a, b) => {
		return (severityOrder[a[1][0].severity] ?? 5) - (severityOrder[b[1][0].severity] ?? 5);
	});

	for (const [type, findings] of sortedTypes) {
		const sev = findings[0].severity;
		const icon = getSeverityIcon(sev);

		console.log(`\n${icon} ${chalk.bold(type)} (${findings.length})`);
		console.log(chalk.dim(`   ${findings[0].message}`));
		if (findings[0].fix) {
			console.log(chalk.cyan(`   Fix: ${findings[0].fix.split("\n")[0]}`));
		}
		console.log("   Files:");

		const maxFiles = 5;
		findings.slice(0, maxFiles).forEach((f) => {
			const loc = f.line ? `${f.file}:${f.line}` : f.file;
			console.log(chalk.dim(`   - ${loc}`));
		});
		if (findings.length > maxFiles) {
			console.log(chalk.dim(`   ... and ${findings.length - maxFiles} more`));
		}
	}

	// Summary
	console.log(`\n${"─".repeat(50)}`);
	console.log(chalk.bold("Summary"));
	console.log("─".repeat(50));

	const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
	issues.forEach((i) => bySev[i.severity as keyof typeof bySev]++);

	if (bySev.critical) console.log(`${getSeverityIcon("critical")} Critical: ${bySev.critical}`);
	if (bySev.high) console.log(`${getSeverityIcon("high")} High: ${bySev.high}`);
	if (bySev.medium) console.log(`${getSeverityIcon("medium")} Medium: ${bySev.medium}`);
	if (bySev.low) console.log(`${getSeverityIcon("low")} Low: ${bySev.low}`);
	console.log();
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

function toSarif(issues: Issue[], _repoPath: string) {
	return {
		$schema:
			"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		version: "2.1.0",
		runs: [
			{
				tool: {
					driver: {
						name: "redwood-scanner",
						version: "0.1.0",
						informationUri: "https://github.com/redwood-labs/scanner",
					},
				},
				results: issues.map((issue) => ({
					ruleId: issue.type,
					level:
						issue.severity === "critical"
							? "error"
							: issue.severity === "high"
								? "error"
								: "warning",
					message: { text: issue.message },
					locations: [
						{
							physicalLocation: {
								artifactLocation: { uri: issue.file },
								region: { startLine: issue.line || 1 },
							},
						},
					],
				})),
			},
		],
	};
}

program.parse();
