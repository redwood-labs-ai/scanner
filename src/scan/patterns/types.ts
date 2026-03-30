/**
 * Pattern definition types
 */

export type Severity = "critical" | "high" | "medium" | "low";

export interface Pattern {
	/** Unique identifier for the pattern */
	name: string;

	/** Regex to match dangerous code */
	regex: RegExp;

	/** Severity level */
	severity: Severity;

	/** Human-readable description of the issue */
	message: string;

	/** Suggested fix */
	fix: string;

	/** File extensions this pattern applies to (e.g., ['.rs', '.go']) */
	fileTypes?: string[];
}

/**
 * Helper to define a pattern with type checking
 */
export function definePattern(pattern: Pattern): Pattern {
	return pattern;
}

/**
 * Helper to define multiple patterns
 */
export function definePatterns(patterns: Pattern[]): Pattern[] {
	return patterns;
}
