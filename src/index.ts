/**
 * Redwood Scanner
 * Security scanner for AI-native codebases
 *
 * @example
 * ```typescript
 * import { scan, validateAgentChain, loadConfig } from '@redwood-labs/scanner';
 *
 * // Full security scan
 * const issues = await scan('./my-repo');
 *
 * // Agent chain validation only
 * const chainIssues = await validateAgentChain('./my-repo');
 *
 * // Load configuration
 * const config = await loadConfig('./my-repo');
 * ```
 */

export { validateAgentChain } from "./scan/agent-chain-validator.js";
export { loadConfig, loadConfigFromPath, type RedwoodConfig } from "./scan/config.js";
export { scanDependencies } from "./scan/deps.js";
export { type Issue, type ScanOptions, scan } from "./scan/engine.js";
export { scanMCP } from "./scan/mcp.js";
export { scanPatterns } from "./scan/patterns.js";
export { scanSecrets } from "./scan/secrets.js";
