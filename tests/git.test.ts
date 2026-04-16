/**
 * Unit tests for git diff utilities.
 *
 * Tests verify:
 * 1. getChangedFiles() returns correct set of changed files
 * 2. getChangedHunks() parses hunk headers correctly
 * 3. isLineChanged() correctly identifies lines within changed hunks
 * 4. getDiffInfo() combines both correctly
 * 5. Error handling for invalid repos and refs
 */

import * as assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { getChangedFiles, getChangedHunks, getDiffInfo, isLineChanged } from "../src/scan/git.js";

/**
 * Create a temporary git repo with an initial commit,
 * then create a branch with changes for testing diff operations.
 */
function createTestRepo(): { repoPath: string; cleanup: () => void } {
	const tmpDir = mkdtempSync(join(tmpdir(), "redwood-git-test-"));
	const repoPath = tmpDir;

	try {
		// Init repo with an explicit initial branch — git's default varies by
		// init.defaultBranch (older git / fresh macOS defaults to "master"), and
		// the tests below all diff against "main".
		execFileSync("git", ["init", "-b", "main", repoPath], { stdio: "pipe" });
		execFileSync("git", ["config", "user.email", "test@test.com"], {
			cwd: repoPath,
			stdio: "pipe",
		});
		execFileSync("git", ["config", "user.name", "Test"], {
			cwd: repoPath,
			stdio: "pipe",
		});

		// Create initial files on main branch
		writeFileSync(join(repoPath, "unchanged.ts"), "export const version = '1.0.0';\n");
		writeFileSync(
			join(repoPath, "modified.ts"),
			"export const secret = 'old';\nconst x = 1;\nconst y = 2;\n"
		);
		mkdirSync(join(repoPath, "subdir"), { recursive: true });
		writeFileSync(
			join(repoPath, "subdir", "config.ts"),
			"export const config = { debug: false };\n"
		);

		execFileSync("git", ["add", "."], { cwd: repoPath, stdio: "pipe" });
		execFileSync("git", ["commit", "-m", "initial"], {
			cwd: repoPath,
			stdio: "pipe",
		});

		// Create a feature branch with changes
		execFileSync("git", ["checkout", "-b", "feature"], {
			cwd: repoPath,
			stdio: "pipe",
		});

		// Modify an existing file (change lines 1 and 2)
		writeFileSync(
			join(repoPath, "modified.ts"),
			"export const secret = 'new-secret-value';\nconst x = 1;\nconst y = 2;\nconst z = 3;\n"
		);

		// Add a new file
		writeFileSync(
			join(repoPath, "added.ts"),
			"export const NEW_API_KEY = 'sk-1234567890abcdef';\n"
		);

		// Delete the subdir file
		rmSync(join(repoPath, "subdir", "config.ts"));

		execFileSync("git", ["add", "."], { cwd: repoPath, stdio: "pipe" });
		execFileSync("git", ["commit", "-m", "feature changes"], {
			cwd: repoPath,
			stdio: "pipe",
		});

		return {
			repoPath,
			cleanup: () => {
				try {
					rmSync(tmpDir, { recursive: true, force: true });
				} catch {}
			},
		};
	} catch (e) {
		// Clean up on failure
		try {
			rmSync(tmpDir, { recursive: true, force: true });
		} catch {}
		throw e;
	}
}

describe("Git Diff Utilities", () => {
	let repoPath: string;
	let cleanup: () => void;

	before(() => {
		const repo = createTestRepo();
		repoPath = repo.repoPath;
		cleanup = repo.cleanup;
	});

	after(() => {
		cleanup();
	});

	describe("getChangedFiles", () => {
		it("should return modified and added files", () => {
			const files = getChangedFiles(repoPath, "main");
			assert.ok(files.has("modified.ts"), "Should include modified.ts");
			assert.ok(files.has("added.ts"), "Should include added.ts");
		});

		it("should not include unchanged files", () => {
			const files = getChangedFiles(repoPath, "main");
			assert.ok(!files.has("unchanged.ts"), "Should not include unchanged.ts");
		});

		it("should return a Set", () => {
			const files = getChangedFiles(repoPath, "main");
			assert.ok(files instanceof Set, "Should return a Set");
		});

		it("should handle git ref that exists", () => {
			const files = getChangedFiles(repoPath, "main");
			assert.ok(files.size > 0, "Should find changes vs main");
		});

		it("should work with HEAD~1 ref", () => {
			const files = getChangedFiles(repoPath, "HEAD~1");
			assert.ok(files.size > 0, "Should find changes vs HEAD~1");
		});
	});

	describe("getChangedHunks", () => {
		it("should return hunk ranges for modified files", () => {
			const hunks = getChangedHunks(repoPath, "main");
			const modifiedHunks = hunks.get("modified.ts");
			assert.ok(modifiedHunks, "Should have hunks for modified.ts");
			assert.ok(modifiedHunks.length > 0, "Should have at least one hunk");
		});

		it("should return hunk ranges for added files", () => {
			const hunks = getChangedHunks(repoPath, "main");
			const addedHunks = hunks.get("added.ts");
			assert.ok(addedHunks, "Should have hunks for added.ts");
			assert.ok(addedHunks.length > 0, "Should have hunks for new file");
		});

		it("should not include hunks for unchanged files", () => {
			const hunks = getChangedHunks(repoPath, "main");
			assert.ok(!hunks.has("unchanged.ts"), "Should not have hunks for unchanged.ts");
		});

		it("should return valid line ranges [start, end]", () => {
			const hunks = getChangedHunks(repoPath, "main");
			for (const [file, ranges] of hunks) {
				for (const [start, end] of ranges) {
					assert.ok(Number.isInteger(start), `Start should be integer for ${file}`);
					assert.ok(Number.isInteger(end), `End should be integer for ${file}`);
					assert.ok(start >= 0, `Start should be >= 0 for ${file}`);
					assert.ok(end >= start, `End should >= start for ${file}`);
				}
			}
		});
	});

	describe("isLineChanged", () => {
		it("should return true for lines within a hunk", () => {
			const hunks: [number, number][] = [[5, 10]];
			assert.ok(isLineChanged(5, hunks), "Line 5 should be changed");
			assert.ok(isLineChanged(7, hunks), "Line 7 should be changed");
			assert.ok(isLineChanged(10, hunks), "Line 10 should be changed");
		});

		it("should return false for lines outside hunks", () => {
			const hunks: [number, number][] = [[5, 10]];
			assert.ok(!isLineChanged(4, hunks), "Line 4 should not be changed");
			assert.ok(!isLineChanged(11, hunks), "Line 11 should not be changed");
			assert.ok(!isLineChanged(1, hunks), "Line 1 should not be changed");
		});

		it("should return false for undefined hunks", () => {
			assert.ok(!isLineChanged(5, undefined), "Should return false for undefined hunks");
		});

		it("should return false for empty hunks array", () => {
			assert.ok(!isLineChanged(5, []), "Should return false for empty hunks");
		});

		it("should handle multiple non-contiguous hunks", () => {
			const hunks: [number, number][] = [
				[1, 3],
				[10, 15],
				[20, 22],
			];
			assert.ok(isLineChanged(2, hunks), "Line 2 in first hunk");
			assert.ok(isLineChanged(12, hunks), "Line 12 in second hunk");
			assert.ok(isLineChanged(21, hunks), "Line 21 in third hunk");
			assert.ok(!isLineChanged(5, hunks), "Line 5 between hunks");
			assert.ok(!isLineChanged(18, hunks), "Line 18 between hunks");
		});

		it("should handle single-line hunks", () => {
			const hunks: [number, number][] = [[5, 5]];
			assert.ok(isLineChanged(5, hunks), "Single line hunk should match");
			assert.ok(!isLineChanged(4, hunks), "Line before should not match");
			assert.ok(!isLineChanged(6, hunks), "Line after should not match");
		});
	});

	describe("getDiffInfo", () => {
		it("should return both changedFiles and changedHunks", () => {
			const info = getDiffInfo(repoPath, "main");
			assert.ok(info.changedFiles instanceof Set, "changedFiles should be a Set");
			assert.ok(info.changedHunks instanceof Map, "changedHunks should be a Map");
		});

		it("should have consistent data between files and hunks", () => {
			const info = getDiffInfo(repoPath, "main");
			// Every file in changedHunks should be in changedFiles
			for (const file of info.changedHunks.keys()) {
				assert.ok(
					info.changedFiles.has(file),
					`File ${file} in hunks should also be in changedFiles`
				);
			}
		});
	});

	describe("Error Handling", () => {
		it("should throw for non-git directory", () => {
			const tmpDir = mkdtempSync(join(tmpdir(), "redwood-notgit-"));
			try {
				assert.throws(
					() => getChangedFiles(tmpDir, "main"),
					/Not a git repository/,
					"Should throw for non-git directory"
				);
			} finally {
				rmSync(tmpDir, { recursive: true, force: true });
			}
		});

		it("should throw for non-existent git ref", () => {
			assert.throws(
				() => getChangedFiles(repoPath, "nonexistent-branch-12345"),
				/Git ref not found/,
				"Should throw for non-existent ref"
			);
		});

		it("should throw for invalid path", () => {
			assert.throws(
				() => getChangedFiles("/tmp/definitely-not-a-real-dir-12345", "main"),
				/Not a git repository/,
				"Should throw for non-existent path"
			);
		});
	});
});
