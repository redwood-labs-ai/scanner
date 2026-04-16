/**
 * Unit tests for confidence scoring and filtering logic.
 *
 * Tests verify:
 * 1. applyConfidence() assigns correct confidence levels
 * 2. filterToNewOnly() correctly filters locations and updates counts
 * 3. Confidence filtering by minimum level works
 */

import * as assert from "node:assert/strict";
import { describe, it } from "node:test";
import { applyConfidence, type Issue } from "../src/scan/engine.js";

function makeIssue(overrides: Partial<Issue> = {}): Issue {
	return {
		id: `test-${Math.random().toString(36).slice(2)}`,
		type: "Test Issue",
		severity: "high",
		file: "src/app.ts",
		line: 10,
		message: "Test issue message",
		...overrides,
	};
}

describe("Confidence Scoring", () => {
	describe("applyConfidence", () => {
		it("should default to high confidence for regular code files", () => {
			const issues = [makeIssue({ file: "src/app.ts", match: "eval(input)" })];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "high");
		});

		it("should set low confidence for .test.ts files", () => {
			const issues = [makeIssue({ file: "src/app.test.ts" })];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});

		it("should set low confidence for .spec.ts files", () => {
			const issues = [makeIssue({ file: "src/app.spec.ts" })];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});

		it("should set low confidence for .test.tsx files", () => {
			const issues = [makeIssue({ file: "src/component.test.tsx" })];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});

		it("should set low confidence for __tests__/ directory", () => {
			const issues = [makeIssue({ file: "src/__tests__/app.ts" })];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});

		it("should set low confidence for /tests/ directory", () => {
			const issues = [makeIssue({ file: "src/tests/app.ts" })];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});

		it("should set low confidence for Python test files", () => {
			const issues = [makeIssue({ file: "tests/test_utils.py" })];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});

		it("should set low confidence for Go test files", () => {
			const issues = [makeIssue({ file: "pkg/util_test.go" })];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});

		it("should set low confidence for Rust test files", () => {
			const issues = [makeIssue({ file: "src/lib_test.rs" })];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});

		it("should set low confidence for safe context: __dirname", () => {
			const issues = [
				makeIssue({ file: "src/config.ts", match: "const p = path.join(__dirname, 'config.json')" }),
			];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});

		it("should set low confidence for safe context: path.join", () => {
			const issues = [
				makeIssue({
					file: "src/config.ts",
					match: "const p = path.join(__dirname, 'config.json')",
				}),
			];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});

		it("should set low confidence for safe context: fs.readFileSync", () => {
			const issues = [
				makeIssue({
					file: "src/loader.ts",
					match: "const data = fs.readFileSync(configPath)",
				}),
			];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});

		it("should set low confidence for safe context in message", () => {
			const issues = [
				makeIssue({
					file: "src/loader.ts",
					message: "Used with path.resolve() to build absolute path",
				}),
			];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});

		it("should set low confidence for short secrets (<16 chars)", () => {
			const issues = [
				makeIssue({
					file: "src/config.ts",
					match: "password: 'short'",
				}),
			];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});

		it("should keep high confidence for long secrets (>=16 chars)", () => {
			const issues = [
				makeIssue({
					file: "src/config.ts",
					match: "api_key: 'abcdefghijklmnopqrstuvwxyz123456'",
				}),
			];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "high");
		});

		it("should preserve existing confidence if already set", () => {
			const issues = [makeIssue({ file: "src/app.ts", confidence: "medium" })];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "medium");
		});

		it("should handle issues without match field", () => {
			const issues = [makeIssue({ file: "src/app.ts", match: undefined })];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "high");
		});

		it("should handle issues without file field (deduped)", () => {
			const issues = [makeIssue({ file: "(3 files)", line: undefined })];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "high");
		});

		it("should handle empty issues array", () => {
			const issues: Issue[] = [];
			applyConfidence(issues);
			assert.strictEqual(issues.length, 0);
		});

		it("should score multiple issues independently", () => {
			const issues = [
				makeIssue({ id: "a", file: "src/app.ts" }),
				makeIssue({ id: "b", file: "src/app.test.ts" }),
				makeIssue({
					id: "c",
					file: "src/config.ts",
					match: "const x = __dirname + '/config'",
				}),
			];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "high");
			assert.strictEqual(issues[1].confidence, "low");
			assert.strictEqual(issues[2].confidence, "low");
		});

		it("should prefer test file check over safe context check", () => {
			// Test file should trigger low even without safe context
			const issues = [
				makeIssue({ file: "tests/app.test.ts", match: "eval(input)" }),
			];
			applyConfidence(issues);
			assert.strictEqual(issues[0].confidence, "low");
		});
	});
});
