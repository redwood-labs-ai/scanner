/**
 * LLM Prompt Generation
 * Generates copy-paste ready prompts for AI assistants to fix security issues
 */

import type { Issue } from "./scan/engine.js";

interface GroupedIssue {
	type: string;
	severity: Issue["severity"];
	count: number;
	files: { file: string; line?: number }[];
	message: string;
	fix: string;
}

/**
 * Generate an LLM-ready prompt from scan issues
 * Auto-groups issues when there are more than 20
 */
export function generatePrompt(issues: Issue[]): string {
	// Filter out bypassed issues (they have "(bypassed)" in the type)
	const actionable = issues.filter((i) => !i.type.includes("(bypassed)"));

	if (actionable.length === 0) {
		return "";
	}

	// Auto-group if >20 issues for readability
	const shouldGroup = actionable.length > 20;

	return shouldGroup
		? generateGroupedPrompt(groupIssues(actionable))
		: generateUngroupedPrompt(actionable);
}

/**
 * Group issues by type, sorted by severity then count
 */
function groupIssues(issues: Issue[]): GroupedIssue[] {
	const groups = new Map<string, GroupedIssue>();

	for (const issue of issues) {
		const key = issue.type;

		const existing = groups.get(key);
		if (existing) {
			existing.count++;
			// Keep first 10 file references
			if (existing.files.length < 10) {
				existing.files.push({ file: issue.file, line: issue.line });
			}
		} else {
			groups.set(key, {
				type: issue.type,
				severity: issue.severity,
				count: 1,
				files: [{ file: issue.file, line: issue.line }],
				message: issue.message,
				fix: issue.fix || "",
			});
		}
	}

	// Sort by severity then count
	const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
	return Array.from(groups.values()).sort((a, b) => {
		const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
		if (sevDiff !== 0) return sevDiff;
		return b.count - a.count;
	});
}

/**
 * Generate prompt for ungrouped issues (<= 20 issues)
 * Shows each issue individually with full context
 */
function generateUngroupedPrompt(issues: Issue[]): string {
	const lines: string[] = [];

	lines.push("Please fix the following security issues in my codebase:");
	lines.push("");

	for (let i = 0; i < issues.length; i++) {
		const issue = issues[i];
		lines.push(`${i + 1}. ${issue.type}`);
		lines.push(`   File: ${issue.file}${issue.line ? `, Line ${issue.line}` : ""}`);
		lines.push(`   Problem: ${issue.message}`);
		if (issue.match) {
			lines.push(`   Current code: ${issue.match}`);
		}
		if (issue.fix) {
			lines.push(`   Required fix: ${issue.fix}`);
		}
		lines.push("");
	}

	lines.push("For each issue, show me the exact code change needed.");

	return lines.join("\n");
}

/**
 * Generate prompt for grouped issues (> 20 issues)
 * Collapses by type with representative examples
 */
function generateGroupedPrompt(grouped: GroupedIssue[]): string {
	const lines: string[] = [];

	lines.push("Please fix the following security issues in my codebase:");
	lines.push("");

	for (let i = 0; i < grouped.length; i++) {
		const group = grouped[i];
		lines.push(`${i + 1}. ${group.type} (${group.count} instances)`);
		lines.push(`   Severity: ${group.severity.toUpperCase()}`);
		lines.push(`   Problem: ${group.message}`);
		if (group.fix) {
			lines.push(`   Fix: ${group.fix}`);
		}
		lines.push(`   Files:`);
		for (const f of group.files.slice(0, 5)) {
			lines.push(`     - ${f.file}${f.line ? `:${f.line}` : ""}`);
		}
		if (group.count > 5) {
			lines.push(`     ... and ${group.count - 5} more files`);
		}
		lines.push("");
	}

	lines.push("For each category, show me a representative fix I can apply across files.");

	return lines.join("\n");
}
