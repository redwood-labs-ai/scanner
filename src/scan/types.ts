/**
 * Shared types for the scan module
 */

export interface Finding {
	id: string;
	severity: "critical" | "high" | "medium" | "low" | "info";
	title: string;
	description: string;
	file?: string;
	line?: number;
	column?: number;
	code?: string;
	tool?: string;
	category?: string;
	fix?: string;
	confidence?: "high" | "medium" | "low";
}

export interface ScanResult {
	findings: Finding[];
	summary: {
		total: number;
		critical: number;
		high: number;
		medium: number;
		low: number;
	};
	metadata?: {
		duration?: number;
		filesScanned?: number;
		repository?: string;
	};
}

export interface ScanJob {
	id: string;
	repository: string;
	repoPath?: string; // alias for backwards compat
	branch?: string;
	commit?: string;
	status: "pending" | "running" | "completed" | "failed";
	createdAt: Date;
	completedAt?: Date;
	result?: ScanResult;
}

// Re-export Issue as Finding alias for backwards compatibility
export type Issue = Finding;
