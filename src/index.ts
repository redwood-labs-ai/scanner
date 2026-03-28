/**
 * Redwood Scanner
 * Security scanner for AI-native codebases
 * 
 * @example
 * ```typescript
 * import { scan, validateAgentChain } from '@redwoodlabs/scanner';
 * 
 * // Full security scan
 * const issues = await scan('./my-repo');
 * 
 * // Agent chain validation only
 * const chainIssues = await validateAgentChain('./my-repo');
 * ```
 */

export { scan, type Issue, type ScanOptions } from './scan/engine.js';
export { validateAgentChain } from './scan/agent-chain-validator.js';
export { scanPatterns } from './scan/patterns.js';
export { scanSecrets } from './scan/secrets.js';
export { scanMCP } from './scan/mcp.js';
export { scanDependencies } from './scan/deps.js';
