/**
 * FP tolerance baseline tests
 *
 * Scans test/fixtures/clean/ and fails if any security findings are
 * reported. These fixtures represent known-good code patterns that
 * should NOT trigger false positives.
 *
 * Run: npm test (which runs tsx --test)
 *      or: npx tsx --test test/fp-baseline.test.ts
 */

import { readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, it } from "node:test";
import { scan } from "../src/scan/engine.js";

const FIXTURES_DIR = join(import.meta.dirname, "fixtures", "clean");

function getFixtureFiles(dir: string): string[] {
	const files: string[] = [];
	for (const entry of readdirSync(dir)) {
		const fullPath = join(dir, entry);
		const stat = statSync(fullPath);
		if (stat.isFile()) {
			files.push(fullPath);
		}
	}
	return files.sort();
}

describe("FP tolerance baselines", () => {
	it("should produce zero findings on clean fixtures", async () => {
		const issues = await scan(FIXTURES_DIR, { quiet: true });

		if (issues.length > 0) {
			const summary = issues
				.map((i) => {
					const loc = i.line ? `${i.file}:${i.line}` : i.file;
					return `  ${i.severity} ${i.type} at ${loc}\n    ${i.message}`;
				})
				.join("\n");

			const msg = `False positive regression detected!\n\n${issues.length} finding(s) in clean fixtures:\n\n${summary}\n\nThese patterns should NOT trigger findings. If this is a new FP, fix the pattern. If this is intentional, update the fixture.`;

			throw new Error(msg);
		}
	});

	// Per-file tests give clearer error messages about which fixture broke
	for (const file of getFixtureFiles(FIXTURES_DIR)) {
		const relName = relative(FIXTURES_DIR, file);
		it(`clean/${relName} should produce zero findings`, async () => {
			const dir = join(FIXTURES_DIR, "..");
			const issues = await scan(dir, {
				quiet: true,
				config: {
					scanners: {
						secrets: true,
						dependencies: false,
						patterns: true,
						mcp: true,
						agentChain: false,
					},
				},
			});

			// Filter to only findings in this specific fixture file
			const fileIssues = issues.filter((i) => i.file === relName || i.file?.includes(relName));

			if (fileIssues.length > 0) {
				const details = fileIssues.map((i) => `  ${i.severity} ${i.type}: ${i.message}`).join("\n");
				throw new Error(
					`False positive in ${relName}:\n${details}\n\nThis pattern should NOT trigger a finding.`
				);
			}
		});
	}
});
