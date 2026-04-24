/**
 * Pattern aggregator
 *
 * Imports all patterns from language-specific modules and exports
 * a unified DANGEROUS_PATTERNS array for the scanner.
 */

// Cross-language and config patterns
import commonPatterns from "./common/index.js";
import configPatterns from "./config/index.js";
import cppPatterns from "./cpp/index.js";
import goPatterns from "./go/index.js";
import javascriptPatterns from "./javascript/index.js";
import phpPatterns from "./php/index.js";
import pythonPatterns from "./python/index.js";
import rubyPatterns from "./ruby/index.js";
// Language-specific patterns
import rustPatterns from "./rust/index.js";
import type { Pattern } from "./types.js";

/**
 * All dangerous patterns aggregated from all modules
 */
export const DANGEROUS_PATTERNS: Pattern[] = [
	...rustPatterns,
	...javascriptPatterns,
	...pythonPatterns,
	...goPatterns,
	...rubyPatterns,
	...phpPatterns,
	...cppPatterns,
	...commonPatterns,
	...configPatterns,
];

// Re-export types
export type { Pattern, Severity } from "./types.js";
export { definePattern, definePatterns } from "./types.js";

// Stats
export const patternStats = {
	total: DANGEROUS_PATTERNS.length,
	byLanguage: {
		rust: rustPatterns.length,
		javascript: javascriptPatterns.length,
		python: pythonPatterns.length,
		go: goPatterns.length,
		ruby: rubyPatterns.length,
		php: phpPatterns.length,
		cpp: cppPatterns.length,
		common: commonPatterns.length,
		config: configPatterns.length,
	},
	bySeverity: {
		critical: DANGEROUS_PATTERNS.filter((p) => p.severity === "critical").length,
		high: DANGEROUS_PATTERNS.filter((p) => p.severity === "high").length,
		medium: DANGEROUS_PATTERNS.filter((p) => p.severity === "medium").length,
		low: DANGEROUS_PATTERNS.filter((p) => p.severity === "low").length,
	},
};
