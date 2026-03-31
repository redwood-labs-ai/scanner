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
 * Simple YAML parser for basic config structures
 * Only supports flat structures with nested objects and arrays
 */
function parseYaml(content: string): Record<string, unknown> {
	const result: Record<string, unknown> = {};
	const lines = content.split("\n");
	let _currentKey: string | null = null;
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
				_currentKey = key;
				currentNested = {};
				result[key] = currentNested;
				nestedKey = key;
			} else {
				// Simple key-value
				_currentKey = key;
				result[key] = parseValue(value);
				currentNested = null;
				nestedKey = null;
			}
		}
	}

	return result;
}

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
