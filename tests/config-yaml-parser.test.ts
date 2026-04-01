/**
 * Tests for the YAML parser in src/scan/config.ts
 */

import * as assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseValue, parseYaml } from "../src/scan/config.ts";

describe("YAML Parser Edge Cases", () => {
	it("should parse simple flat config", () => {
		const yaml = `
severity: high
maxFindings: 50
		`;
		const result = parseYaml(yaml);
		assert.strictEqual(result.severity, "high");
		assert.strictEqual(result.maxFindings, 50);
	});

	it("should parse nested objects with multiple keys", () => {
		const yaml = `
scanners:
  secrets: true
  dependencies: false
		`;
		const result = parseYaml(yaml);

		assert.ok(result.scanners && typeof result.scanners === "object");
		const scanners = result.scanners as Record<string, unknown>;
		assert.strictEqual(scanners.secrets, true);
		assert.strictEqual(scanners.dependencies, false);
	});

	it("should handle multiple nested sections", () => {
		const yaml = `
scanners:
  secrets: true
output:
  verbose: false
		`;
		const result = parseYaml(yaml);

		assert.ok(result.scanners, "scanners should exist at top level");
		assert.ok(result.output, "output should exist at top level");
		const scanners = result.scanners as Record<string, unknown>;
		const output = result.output as Record<string, unknown>;
		assert.strictEqual(scanners.secrets, true);
		assert.strictEqual(output.verbose, false);
	});

	it("should parse top-level arrays", () => {
		const yaml = `
ignore:
  - node_modules
  - dist
		`;
		const result = parseYaml(yaml);

		assert.ok(Array.isArray(result.ignore), "ignore should be an array");
		const ignore = result.ignore as string[];
		assert.strictEqual(ignore.length, 2);
		assert.strictEqual(ignore[0], "node_modules");
		assert.strictEqual(ignore[1], "dist");
	});

	it("should parse array items with proper types", () => {
		const yaml = `
values:
  - 123
  - true
  - hello
		`;
		const result = parseYaml(yaml);

		assert.ok(Array.isArray(result.values), "values should be an array");
		const values = result.values as unknown[];
		assert.strictEqual(values[0], 123);
		assert.strictEqual(values[1], true);
		assert.strictEqual(values[2], "hello");
	});

	it("should handle colons in unquoted values", () => {
		const yaml = `
time: 10:30
url: https://example.com
		`;
		const result = parseYaml(yaml);

		assert.strictEqual(result.time, "10:30");
		assert.strictEqual(result.url, "https://example.com");
	});

	it("should parse the real .redwoodrc.yaml.example", () => {
		const yaml = `
severity: high

ignore:
  - '**/node_modules/**'
  - '**/dist/**'

scanners:
  secrets: true
  dependencies: true

output:
  json: false
  verbose: false
		`;
		const result = parseYaml(yaml);

		assert.strictEqual(result.severity, "high");

		assert.ok(Array.isArray(result.ignore), "ignore should be array");
		const ignore = result.ignore as string[];
		assert.strictEqual(ignore.length, 2);
		assert.strictEqual(ignore[0], "**/node_modules/**");
		assert.strictEqual(ignore[1], "**/dist/**");

		assert.ok(result.scanners, "scanners should exist");
		const scanners = result.scanners as Record<string, unknown>;
		assert.strictEqual(scanners.secrets, true);
		assert.strictEqual(scanners.dependencies, true);

		assert.ok(result.output, "output should exist at top level");
		const output = result.output as Record<string, unknown>;
		assert.strictEqual(output.json, false);
		assert.strictEqual(output.verbose, false);
	});

	it("should handle deeply nested structures", () => {
		const yaml = `
level1:
  level2:
    level3: deep
		`;
		const result = parseYaml(yaml);

		assert.ok(result.level1, "level1 should exist");
		const level1 = result.level1 as Record<string, unknown>;
		assert.ok(level1.level2, "level2 should exist");
		const level2 = level1.level2 as Record<string, unknown>;
		assert.strictEqual(level2.level3, "deep");
	});

	it("should handle quoted strings", () => {
		const yaml = `
single: 'hello world'
double: "foo bar"
		`;
		const result = parseYaml(yaml);

		assert.strictEqual(result.single, "hello world");
		assert.strictEqual(result.double, "foo bar");
	});

	it("should handle comments", () => {
		const yaml = `
# This is a comment
key: value # inline comment not supported, included in value
# Another comment
other: stuff
		`;
		const result = parseYaml(yaml);

		assert.ok(result.key);
		assert.strictEqual(result.other, "stuff");
	});
});

describe("parseValue", () => {
	it("should parse booleans", () => {
		assert.strictEqual(parseValue("true"), true);
		assert.strictEqual(parseValue("false"), false);
		assert.strictEqual(parseValue("TRUE"), true);
		assert.strictEqual(parseValue("FALSE"), false);
	});

	it("should parse null", () => {
		assert.strictEqual(parseValue("null"), null);
		assert.strictEqual(parseValue("~"), null);
		assert.strictEqual(parseValue(""), null);
	});

	it("should parse integers", () => {
		assert.strictEqual(parseValue("42"), 42);
		assert.strictEqual(parseValue("-10"), -10);
		assert.strictEqual(parseValue("0"), 0);
	});

	it("should parse floats", () => {
		assert.strictEqual(parseValue("3.14"), 3.14);
		assert.strictEqual(parseValue("-2.5"), -2.5);
	});

	it("should parse quoted strings", () => {
		assert.strictEqual(parseValue('"hello"'), "hello");
		assert.strictEqual(parseValue("'world'"), "world");
	});

	it("should return plain strings as-is", () => {
		assert.strictEqual(parseValue("hello"), "hello");
		assert.strictEqual(parseValue("10:30"), "10:30");
	});
});
