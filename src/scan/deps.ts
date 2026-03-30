import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Issue } from "./engine.js";

export async function scanDependencies(repoPath: string): Promise<Issue[]> {
	const issues: Issue[] = [];

	// Check for package.json (Node.js)
	const packageJsonPath = join(repoPath, "package.json");
	if (existsSync(packageJsonPath)) {
		const npmIssues = await scanNpmDependencies(repoPath);
		issues.push(...npmIssues);
	}

	// Check for Cargo.toml (Rust)
	const cargoTomlPath = join(repoPath, "Cargo.toml");
	if (existsSync(cargoTomlPath)) {
		const cargoIssues = await scanCargoDependencies(repoPath);
		issues.push(...cargoIssues);
	}

	// Check for requirements.txt or pyproject.toml (Python)
	const requirementsPath = join(repoPath, "requirements.txt");
	const pyprojectPath = join(repoPath, "pyproject.toml");
	if (existsSync(requirementsPath) || existsSync(pyprojectPath)) {
		const pipIssues = await scanPipDependencies(repoPath);
		issues.push(...pipIssues);
	}

	return issues;
}

async function scanNpmDependencies(repoPath: string): Promise<Issue[]> {
	const issues: Issue[] = [];

	try {
		// Run npm audit
		const result = execSync("npm audit --json 2>/dev/null || true", {
			cwd: repoPath,
			encoding: "utf-8",
			maxBuffer: 10 * 1024 * 1024,
		});

		if (result.trim()) {
			const audit = JSON.parse(result);

			if (audit.vulnerabilities) {
				for (const [pkg, vuln] of Object.entries(audit.vulnerabilities as Record<string, any>)) {
					const severity = mapSeverity(vuln.severity);

					issues.push({
						id: `npm-${pkg}`,
						type: "Vulnerable Dependency",
						severity,
						file: "package.json",
						message: `${pkg} has ${vuln.severity} severity vulnerability`,
						fix: vuln.fixAvailable
							? `Run: npm update ${pkg}`
							: "No fix available, consider replacing this package",
					});
				}
			}
		}
	} catch (_error) {
		// npm audit not available or failed
	}

	return issues;
}

async function scanCargoDependencies(repoPath: string): Promise<Issue[]> {
	const issues: Issue[] = [];

	try {
		const result = execSync("cargo audit --json 2>/dev/null || true", {
			cwd: repoPath,
			encoding: "utf-8",
			maxBuffer: 10 * 1024 * 1024,
		});

		if (result.trim()) {
			const audit = JSON.parse(result);

			if (audit.vulnerabilities?.list) {
				for (const vuln of audit.vulnerabilities.list) {
					issues.push({
						id: `cargo-${vuln.advisory.id}`,
						type: "Vulnerable Dependency",
						severity: mapSeverity(vuln.advisory.severity || "medium"),
						file: "Cargo.toml",
						message: `${vuln.package.name}: ${vuln.advisory.title}`,
						fix: vuln.versions?.patched?.length
							? `Update to version ${vuln.versions.patched[0]}`
							: "No fix available",
					});
				}
			}
		}
	} catch (_error) {
		// cargo audit not available or failed
	}

	return issues;
}

async function scanPipDependencies(repoPath: string): Promise<Issue[]> {
	const issues: Issue[] = [];

	try {
		const result = execSync("pip-audit --format json 2>/dev/null || true", {
			cwd: repoPath,
			encoding: "utf-8",
			maxBuffer: 10 * 1024 * 1024,
		});

		if (result.trim()) {
			const audit = JSON.parse(result);

			for (const vuln of audit) {
				issues.push({
					id: `pip-${vuln.name}-${vuln.id}`,
					type: "Vulnerable Dependency",
					severity: mapSeverity(vuln.severity || "medium"),
					file: "requirements.txt",
					message: `${vuln.name}: ${vuln.description}`,
					fix: vuln.fix_versions?.length
						? `Update to version ${vuln.fix_versions[0]}`
						: "No fix available",
				});
			}
		}
	} catch (_error) {
		// pip-audit not available or failed
	}

	return issues;
}

function mapSeverity(severity: string): Issue["severity"] {
	const lower = severity.toLowerCase();
	if (lower === "critical") return "critical";
	if (lower === "high") return "high";
	if (lower === "moderate" || lower === "medium") return "medium";
	return "low";
}
