/**
 * .redwoodignore file parser and pattern matcher
 * 
 * Similar to .gitignore, allows users to specify glob patterns
 * for files/directories to exclude from scanning.
 */

import { readFileSync, existsSync } from 'fs';
import { join, relative, posix } from 'path';
import { glob } from 'glob';

/**
 * Default directories to ignore across all scanners.
 * This is the centralized list that all scanners should use.
 * Users can add additional patterns via .redwoodignore
 */
export const DEFAULT_IGNORE_DIRS = [
  // JS/Node
  'node_modules', 'dist', 'build', '.next', '.nuxt', 
  // Rust
  'target', 
  // Python
  '__pycache__', '.venv', 'venv', 'env',
  // General version control and dependencies
  '.git', 'vendor', 'third_party', 'deps',
  // Tests (configurable later)
  'test', 'tests', '__tests__', 'spec', 'fixtures',
];

/**
 * Default file extensions to ignore (binary, generated, etc.)
 */
export const DEFAULT_IGNORE_EXTENSIONS = [
  // Minified/generated
  '.min.js', '.map', '.lock',
  // Images
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
  // Compiled/binary
  '.dylib', '.so', '.dll', '.exe', '.o', '.a', '.rlib', '.rmeta',
  '.wasm', '.pyc', '.pyo', '.class', '.jar',
  // Archives
  '.zip', '.tar', '.gz', '.tgz', '.rar', '.7z',
  // Other
  '.pdf', '.doc', '.docx', '.xls', '.xlsx',
];

export interface IgnoreConfig {
  patterns: string[];
  file: string;
}

/**
 * Load .redwoodignore from the repository root
 * Returns an array of glob patterns to ignore
 */
export async function loadRedwoodIgnore(repoPath: string): Promise<IgnoreConfig | null> {
  const ignoreFile = join(repoPath, '.redwoodignore');
  
  if (!existsSync(ignoreFile)) {
    return null;
  }
  
  try {
    const content = readFileSync(ignoreFile, 'utf-8');
    const patterns = parseIgnoreFile(content);
    
    return {
      patterns,
      file: ignoreFile,
    };
  } catch (error) {
    // If we can't read the file, just return empty patterns
    console.error(`Warning: Could not read .redwoodignore: ${error}`);
    return { patterns: [], file: ignoreFile };
  }
}

/**
 * Parse .redwoodignore file content into glob patterns
 * 
 * Supports:
 * - Comments starting with #
 * - Negation patterns starting with !
 * - Directory patterns ending with /
 * - Standard gitignore-style globs
 */
export function parseIgnoreFile(content: string): string[] {
  const patterns: string[] = [];
  const lines = content.split('\n');
  
  for (const line of lines) {
    const trimmed = line.trim();
    
    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    
    // Add the pattern (can include ! for negation)
    patterns.push(trimmed);
  }
  
  return patterns;
}

/**
 * Check if a file path matches any ignore pattern
 * 
 * @param file - Absolute path to the file
 * @param repoPath - Absolute path to repository root
 * @param patterns - Array of glob patterns from .redwoodignore
 * @returns true if the file should be ignored
 */
export function isIgnored(file: string, repoPath: string, patterns: string[]): boolean {
  // Get relative path from repo root
  const relPath = relative(repoPath, file);
  
  // Check both posix-style path and the relative path
  const posixPath = posix.relative(repoPath, file);
  
  for (const pattern of patterns) {
    // Handle negation patterns
    const isNegation = pattern.startsWith('!');
    const actualPattern = isNegation ? pattern.slice(1) : pattern;
    
    // Normalize pattern for glob matching
    let globPattern: string;
    
    // If pattern ends with /, it's a directory-only pattern
    if (actualPattern.endsWith('/')) {
      const dirPattern = actualPattern.slice(0, -1);
      // Check if the file is inside this directory
      if (matchesGlob(relPath, `${dirPattern}/**`) || 
          matchesGlob(posixPath, `${dirPattern}/**`) ||
          relPath.startsWith(dirPattern + '/') ||
          posixPath.startsWith(dirPattern + '/')) {
        return !isNegation;
      }
    } else {
      // File or wildcard pattern
      if (matchesGlob(relPath, actualPattern) || 
          matchesGlob(posixPath, actualPattern)) {
        return !isNegation;
      }
    }
  }
  
  return false;
}

/**
 * Check if a path matches a glob pattern
 */
function matchesGlob(path: string, pattern: string): boolean {
  try {
    // Use glob.sync with matchOnly to check if path matches pattern
    const regexPattern = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, ".*").replace(/\*/g, "[^/]*").replace(/\?/g, "."); const regex = new RegExp("^" + regexPattern + "$"); const result = regex.test(path) ? [path] : [];
    return result.length > 0;
  } catch {
    // If glob fails, fall back to simple string matching
    return path === pattern;
  }
}

/**
 * Check if a directory should be skipped entirely
 * Useful for skipping node_modules, .git, etc.
 */
export function shouldSkipDir(dirName: string, dirPath: string, repoPath: string, patterns: string[]): boolean {
  // Always skip .git
  if (dirName === '.git') {
    return true;
  }
  
  // Check against ignore patterns
  const relPath = relative(repoPath, dirPath);
  const posixPath = posix.relative(repoPath, dirPath);
  
  for (const pattern of patterns) {
    const isNegation = pattern.startsWith('!');
    const actualPattern = isNegation ? pattern.slice(1) : pattern;
    
    // Check if directory name or path matches pattern
    const dirPattern = actualPattern.endsWith('/') ? actualPattern.slice(0, -1) : actualPattern;
    
    if (dirName === dirPattern || 
        matchesGlob(relPath, dirPattern) ||
        matchesGlob(posixPath, dirPattern) ||
        matchesGlob(relPath, `${dirPattern}/*`) ||
        matchesGlob(posixPath, `${dirPattern}/*`)) {
      return !isNegation;
    }
  }
  
  return false;
}
