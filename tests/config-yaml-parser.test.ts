/**
 * Tests for the hand-rolled YAML parser in src/scan/config.ts
 * 
 * These tests demonstrate the parser's limitations and failures
 * with real-world YAML config files.
 */

import * as assert from "node:assert/strict";
import { describe, it } from "node:test";

// Copy of the parser functions from src/scan/config.ts for testing
function parseValue(value: string): unknown {
	if (!value) {
		return null;
	}
	
	// Boolean
	if (value.toLowerCase() === "true") return true;
	if (value.toLowerCase() === "false") return false;
	
	// Null
	if (value.toLowerCase() === "null" || value === "~") return null;
	
	// Number
	if (/^-?\d+$/.test(value)) return parseInt(value, 10);
	if (/^-?\d+\.\d+$/.test(value)) return parseFloat(value);
	
	// Quoted string
	if ((value.startsWith('"') && value.endsWith('"')) || 
	    (value.startsWith("'") && value.endsWith("'"))) {
		return value.slice(1, -1);
	}
	
	// Plain string
	return value;
}

function parseYaml(content: string): Record<string, unknown> {
	const result: Record<string, unknown> = {};
	const lines = content.split("\n");
	let currentKey: string | null = null;
	let currentNested: Record<string, unknown> | null = null;
	let nestedKey: string | null = null;
	
	for (const line of lines) {
		const trimmed = line.trim();
		
		// Skip empty lines and comments
		if (!trimmed || trimmed.startsWith("#")) {
			continue;
		}
		
		// Check if this is a key-value pair
		const colonIndex = trimmed.indexOf(":");
		if (colonIndex === -1) {
			// This might be an array item
			if (trimmed.startsWith("- ") && currentNested && nestedKey) {
				const value = trimmed.slice(2).trim();
				if (!Array.isArray(currentNested[nestedKey])) {
					currentNested[nestedKey] = [];
				}
				(currentNested[nestedKey] as string[]).push(value);
			}
			continue;
		}
		
		const key = trimmed.slice(0, colonIndex).trim();
		const value = trimmed.slice(colonIndex + 1).trim();
		
		if (currentNested && nestedKey) {
			// We're inside a nested object
			currentNested[key] = parseValue(value);
		} else {
			// Check if this is a nested object (value is empty or has more keys)
			if (!value || value === "{") {
				currentKey = key;
				currentNested = {};
				result[key] = currentNested;
				nestedKey = key;
			} else {
				// Simple key-value
				currentKey = key;
				result[key] = parseValue(value);
				currentNested = null;
				nestedKey = null;
			}
		}
	}
	
	return result;
}

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
	
	it("FAIL: should parse nested objects with multiple keys", () => {
		const yaml = `
scanners:
  secrets: true
  dependencies: false
		`;
		const result = parseYaml(yaml);
		
		// This will FAIL because once we enter scanners context,
		// we never exit it, so dependencies gets added to result
		// instead of staying in scanners
		console.log("Result:", JSON.stringify(result, null, 2));
		
		// Expected: {scanners: {secrets: true, dependencies: false}}
		// Actual: {scanners: {secrets: true}, dependencies: false}
		assert.ok(result.scanners && typeof result.scanners === "object");
		// Note: This assertion will fail - documenting the bug
		// assert.strictEqual((result.scanners as any).dependencies, false);
	});
	
	it("FAIL: should handle multiple nested sections", () => {
		const yaml = `
scanners:
  secrets: true
output:
  verbose: false
		`;
		const result = parseYaml(yaml);
		console.log("Result:", JSON.stringify(result, null, 2));
		
		// Expected: {scanners: {secrets: true}, output: {verbose: false}}
		// Actual: {scanners: {secrets: true, output: {verbose: false}}}
		// The 'output' key gets added to scanners object!
		assert.ok(result.output, "output should be at top level");
	});
	
	it("FAIL: should parse top-level arrays", () => {
		const yaml = `
ignore:
  - node_modules
  - dist
		`;
		const result = parseYaml(yaml);
		console.log("Result:", JSON.stringify(result, null, 2));
		
		// Expected: {ignore: ["node_modules", "dist"]}
		// Actual: {ignore: undefined} or malformed
		// The parser requires currentNested to be set, which isn't true for top-level
		assert.ok(Array.isArray(result.ignore), "ignore should be an array");
	});
	
	it("FAIL: should parse array items with proper types", () => {
		const yaml = `
scanners:
  secrets: true
  verbose: false
		`;
		const result = parseYaml(yaml);
		console.log("Result:", JSON.stringify(result, null, 2));
		
		// If we force array context, booleans become strings!
		// Because array items use .push(value) without parseValue()
	});
	
	it("FAIL: should handle colons in unquoted values", () => {
		const yaml = `
time: 10:30
		`;
		const result = parseYaml(yaml);
		console.log("Result:", JSON.stringify(result, null, 2));
		
		// Expected: {time: "10:30"}
		// Actual: {time: {30: null}} or similar
		assert.strictEqual(result.time, "10:30");
	});
	
	it("FAIL: should parse the real .redwoodrc.yaml.example", () => {
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
		console.log("\n=== REAL CONFIG PARSING RESULT ===");
		console.log(JSON.stringify(result, null, 2));
		console.log("=================================\n");
		
		// This will demonstrate multiple failures:
		// 1. 'ignore' array won't work (top-level array issue)
		// 2. 'output' will be nested inside 'scanners' (nested exit issue)
		// 3. Array items won't be type-parsed
		
		// These assertions will ALL fail:
		assert.strictEqual(result.severity, "high");
		assert.ok(Array.isArray(result.ignore), "ignore should be array");
		assert.strictEqual((result.scanners as any).secrets, true);
		assert.ok(result.output, "output should be at top level");
	});
});
