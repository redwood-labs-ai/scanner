/**
 * Git diff utilities for PR/diff scan mode.
 *
 * Provides functions to get changed files and hunks from git diff,
 * enabling scan-only-changed-files and scan-only-changed-lines modes.
 */

import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

export interface DiffInfo {
	/** Set of changed file paths (relative to repo root) */
	changedFiles: Set<string>;
	/** Map of file -> array of [startLine, endLine] ranges for changed lines */
	changedHunks: Map<string, [number, number][]>;
}

/**
 * Run git diff to get changed files between base and HEAD.
 *
 * @param repoPath - Path to the git repository
 * @param base - Base ref to diff against (e.g., "main", "origin/main", "HEAD~3")
 * @returns Set of changed file paths relative to repo root
 */
export function getChangedFiles(repoPath: string, base: string): Set<string> {
	const absPath = resolve(repoPath);

	// Verify it's a git repo
	try {
		execFileSync("git", ["rev-parse", "--git-dir"], {
			cwd: absPath,
			timeout: 5000,
			stdio: ["pipe", "pipe", "pipe"],
		});
	} catch {
		throw new Error(`Not a git repository: ${repoPath}`);
	}

	// Verify the base ref exists
	try {
		execFileSync("git", ["rev-parse", "--verify", base], {
			cwd: absPath,
			timeout: 5000,
			stdio: ["pipe", "pipe", "pipe"],
		});
	} catch {
		throw new Error(`Git ref not found: ${base}. Try 'git fetch' first.`);
	}

	// Get changed files (using triple-dot diff for branch comparison)
	let output: string;
	try {
		output = execFileSync("git", ["diff", "--name-only", "--diff-filter=ACMR", `${base}...HEAD`], {
			cwd: absPath,
			timeout: 30000,
			encoding: "utf-8",
			maxBuffer: 10 * 1024 * 1024,
		});
	} catch {
		// Fallback: try double-dot diff if triple-dot fails (e.g., base is ancestor)
		try {
			output = execFileSync("git", ["diff", "--name-only", "--diff-filter=ACMR", `${base}..HEAD`], {
				cwd: absPath,
				timeout: 30000,
				encoding: "utf-8",
				maxBuffer: 10 * 1024 * 1024,
			});
		} catch (e) {
			throw new Error(`Failed to run git diff: ${e}`);
		}
	}

	const files = new Set<string>();
	for (const line of output.split("\n")) {
		const trimmed = line.trim();
		if (trimmed) {
			files.add(trimmed);
		}
	}

	return files;
}

/**
 * Parse git diff output to extract changed line ranges per file.
 *
 * @param repoPath - Path to the git repository
 * @param base - Base ref to diff against
 * @returns Map of file -> array of [startLine, endLine] ranges
 */
export function getChangedHunks(repoPath: string, base: string): Map<string, [number, number][]> {
	const absPath = resolve(repoPath);

	let output: string;
	try {
		output = execFileSync("git", ["diff", "--unified=0", `${base}...HEAD`], {
			cwd: absPath,
			timeout: 30000,
			encoding: "utf-8",
			maxBuffer: 10 * 1024 * 1024,
		});
	} catch {
		try {
			output = execFileSync("git", ["diff", "--unified=0", `${base}..HEAD`], {
				cwd: absPath,
				timeout: 30000,
				encoding: "utf-8",
				maxBuffer: 10 * 1024 * 1024,
			});
		} catch (e) {
			throw new Error(`Failed to run git diff: ${e}`);
		}
	}

	const hunks = new Map<string, [number, number][]>();
	let currentFile = "";

	for (const line of output.split("\n")) {
		// Match file header: +++ b/path/to/file
		const fileMatch = line.match(/^\+\+\+ b\/(.+)$/);
		if (fileMatch) {
			currentFile = fileMatch[1];
			if (!hunks.has(currentFile)) {
				hunks.set(currentFile, []);
			}
			continue;
		}

		// Match hunk header: @@ -old_start,old_count +new_start,new_count @@
		const hunkMatch = line.match(/^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,(\d+))?\s+@@/);
		if (hunkMatch && currentFile) {
			const start = parseInt(hunkMatch[1], 10);
			const count = hunkMatch[2] ? parseInt(hunkMatch[2], 10) : 1;
			const end = start + count - 1;
			hunks.get(currentFile)?.push([start, Math.max(end, start)]);
		}
	}

	return hunks;
}

/**
 * Get full diff info (changed files + hunks) in one call.
 */
export function getDiffInfo(repoPath: string, base: string): DiffInfo {
	return {
		changedFiles: getChangedFiles(repoPath, base),
		changedHunks: getChangedHunks(repoPath, base),
	};
}

/**
 * Check if a line number falls within any of the changed hunks for a file.
 */
export function isLineChanged(line: number, fileHunks: [number, number][] | undefined): boolean {
	if (!fileHunks || fileHunks.length === 0) return false;
	return fileHunks.some(([start, end]) => line >= start && line <= end);
}
