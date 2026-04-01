/**
 * Configuration loader for .redwoodrc files
 *
 * Supports both JSON (.redwoodrc.json) and YAML (.redwoodrc.yaml) formats
 * Provides defaults and validation for scanner settings
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export interface RedwoodConfig {
	/** Minimum severity threshold to fail the scan */
	severity?: "critical" | "high" | "medium" | "low" | "info";

	/** Glob patterns for files/directories to ignore (in addition to .redwoodignore) */
	ignore?: string[];

	/** Enable/disable specific scanners */
	scanners?: {
		secrets?: boolean;
		dependencies?: boolean;
		patterns?: boolean;
		mcp?: boolean;
		agentChain?: boolean;
	};

	/** Custom severity thresholds per rule type */
	rules?: Record<string, "critical" | "high" | "medium" | "low" | "info" | "off">;

	/** Maximum number of findings per rule type */
	maxFindings?: number;

	/** Output format preferences */
	output?: {
		json?: boolean;
		sarif?: boolean;
		verbose?: boolean;
	};

	/** Custom directories to skip (in addition to defaults) */
	skipDirs?: string[];
}

export const DEFAULT_CONFIG: RedwoodConfig = {
	severity: "critical",
	ignore: [],
	scanners: {
		secrets: true,
		dependencies: true,
		patterns: true,
		mcp: true,
		agentChain: true,
	},
	rules: {},
	maxFindings: 100,
	output: {
		json: false,
		sarif: false,
		verbose: false,
	},
	skipDirs: [],
};

/**
 * Load configuration from a specific file path
 */
export async function loadConfigFromPath(configPath: string): Promise<RedwoodConfig> {
	if (!existsSync(configPath)) {
		console.warn(`Config file not found: ${configPath}`);
		return { ...DEFAULT_CONFIG };
	}

	try {
		const content = readFileSync(configPath, "utf-8");

		// Parse based on file extension
		let parsed: Record<string, unknown>;
		if (configPath.endsWith(".json")) {
			parsed = JSON.parse(content);
		} else if (configPath.endsWith(".yaml") || configPath.endsWith(".yml")) {
			parsed = parseYaml(content);
		} else {
			// Default to JSON parsing
			parsed = JSON.parse(content);
		}

		// Merge with defaults
		return mergeConfig(DEFAULT_CONFIG, parsed);
	} catch (error) {
		console.error(`Warning: Could not parse config file ${configPath}: ${error}`);
		return { ...DEFAULT_CONFIG };
	}
}

/**
 * Load configuration from .redwoodrc.json or .redwoodrc.yaml
 * Searches from the given directory upward to the project root
 */
export async function loadConfig(repoPath: string): Promise<RedwoodConfig> {
	const configPath = findConfigFile(repoPath);

	if (!configPath) {
		return { ...DEFAULT_CONFIG };
	}

	return await loadConfigFromPath(configPath);
}

/**
 * Search for config file starting from repoPath and going upward
 */
function findConfigFile(startPath: string): string | null {
	const pathsToCheck = [
		join(startPath, ".redwoodrc.json"),
		join(startPath, ".redwoodrc.yaml"),
		join(startPath, ".redwoodrc.yml"),
		join(startPath, ".redwoodrc"),
	];

	for (const configPath of pathsToCheck) {
		if (existsSync(configPath)) {
			return configPath;
		}
	}

	return null;
}

/**
 * YAML parser with proper indentation tracking
 * Supports nested objects, arrays, and handles edge cases like colons in values
 */
function parseYaml(content: string): Record<string, unknown> {
	const lines = content.split("\n");

	// Stack entry: the object/array we're building, its indent level, and parent info
	interface StackEntry {
		container: Record<string, unknown> | unknown[];
		indent: number;
		parentKey: string | null;
		parent: Record<string, unknown> | null;
	}

	const root: Record<string, unknown> = {};
	const stack: StackEntry[] = [{ container: root, indent: -1, parentKey: null, parent: null }];

	// Track when we've just seen a key with no value (could become object or array)
	let pendingKey: string | null = null;
	let pendingKeyIndent = -1;
	let pendingKeyParent: Record<string, unknown> | null = null;

	for (const line of lines) {
		// Skip empty lines and full-line comments
		if (!line.trim() || line.trim().startsWith("#")) {
			continue;
		}

		const indent = line.search(/\S/);
		const trimmed = line.trim();

		// Pop stack until we find a context with lower indent
		while (stack.length > 1 && stack[stack.length - 1].indent >= indent) {
			stack.pop();
		}

		// Handle array items
		if (trimmed.startsWith("- ")) {
			const itemValue = trimmed.slice(2).trim();

			// If we have a pending key at a lower indent, this is its array value
			if (pendingKey !== null && pendingKeyIndent < indent && pendingKeyParent) {
				const arr: unknown[] = [];
				pendingKeyParent[pendingKey] = arr;
				stack.push({
					container: arr,
					indent: pendingKeyIndent,
					parentKey: pendingKey,
					parent: pendingKeyParent,
				});
				pendingKey = null;
				pendingKeyParent = null;
			}

			// Add to current array
			const current = stack[stack.length - 1];
			if (Array.isArray(current.container)) {
				current.container.push(parseValue(itemValue));
			}
			continue;
		}

		// Parse key: value
		const colonMatch = trimmed.match(/^([^:]+):\s*(.*)?$/);
		if (!colonMatch) {
			continue;
		}

		const key = colonMatch[1].trim();
		const value = (colonMatch[2] || "").trim();

		// If we have a pending key at a lower indent, this is a nested object under it
		if (pendingKey !== null && pendingKeyIndent < indent && pendingKeyParent) {
			const obj: Record<string, unknown> = {};
			pendingKeyParent[pendingKey] = obj;
			stack.push({
				container: obj,
				indent: pendingKeyIndent,
				parentKey: pendingKey,
				parent: pendingKeyParent,
			});
			pendingKey = null;
			pendingKeyParent = null;
		}

		const current = stack[stack.length - 1];

		// We can only add keys to objects, not arrays
		if (Array.isArray(current.container)) {
			continue;
		}

		if (!value) {
			// Empty value - could be object or array, wait and see
			pendingKey = key;
			pendingKeyIndent = indent;
			pendingKeyParent = current.container;
		} else {
			// Simple key-value pair
			current.container[key] = parseValue(value);
			pendingKey = null;
			pendingKeyParent = null;
		}
	}

	return root;
}

// Export for testing
export { parseValue, parseYaml };

/**
 * Parse a YAML value string to the appropriate type
 */
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
	if (
		(value.startsWith('"') && value.endsWith('"')) ||
		(value.startsWith("'") && value.endsWith("'"))
	) {
		return value.slice(1, -1);
	}

	// Plain string
	return value;
}

/**
 * Merge parsed config with defaults, handling nested structures
 */
function mergeConfig(defaults: RedwoodConfig, parsed: Record<string, unknown>): RedwoodConfig {
	const result = { ...defaults };

	for (const [key, value] of Object.entries(parsed)) {
		if (value === null || value === undefined) {
			continue;
		}

		const configKey = key as keyof RedwoodConfig;

		// Handle nested objects
		if (key === "scanners" && typeof value === "object" && !Array.isArray(value)) {
			result.scanners = { ...defaults.scanners };
			for (const [scannerKey, scannerValue] of Object.entries(value)) {
				if (scannerKey in result.scanners) {
					(result.scanners as any)[scannerKey] = Boolean(scannerValue);
				}
			}
		} else if (key === "rules" && typeof value === "object" && !Array.isArray(value)) {
			result.rules = value as Record<
				string,
				"critical" | "high" | "medium" | "low" | "info" | "off"
			>;
		} else if (key === "output" && typeof value === "object" && !Array.isArray(value)) {
			result.output = { ...defaults.output };
			for (const [outputKey, outputValue] of Object.entries(value)) {
				if (outputKey in result.output) {
					(result.output as any)[outputKey] = outputValue;
				}
			}
		} else if (key === "ignore" && Array.isArray(value)) {
			result.ignore = value as string[];
		} else if (key === "skipDirs" && Array.isArray(value)) {
			result.skipDirs = value as string[];
		} else if (configKey in result && typeof defaults[configKey] === typeof value) {
			(result as any)[configKey] = value;
		}
	}

	return result;
}
