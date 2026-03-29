/**
 * Pattern-based security scanner
 * 
 * Patterns are now organized in src/scan/patterns/ by language:
 * - rust/      - Rust-specific patterns
 * - javascript/ - JS/TS patterns
 * - python/    - Python patterns
 * - go/        - Go patterns
 * - ruby/      - Ruby patterns
 * - php/       - PHP patterns
 * - common/    - Cross-language patterns
 * - config/    - Configuration file patterns
 */

import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative, extname } from 'path';
import type { Issue } from './engine.js';
import { DANGEROUS_PATTERNS, patternStats, type Pattern } from './patterns/index.js';
import { 
  DEFAULT_IGNORE_DIRS, 
  DEFAULT_IGNORE_EXTENSIONS,
  loadRedwoodIgnore, 
  isIgnored, 
  shouldSkipDir 
} from './ignore.js';

/**
 * Inline ignore comment patterns for different languages
 * Supports: // redwood-ignore, # redwood-ignore
 */
const INLINE_IGNORE_PATTERN = /\s*(\/\/|#)\s*redwood-ignore/i;

/**
 * Extract inline ignore comments from a file and map them to line numbers
 * Returns a Set of line numbers that have ignore comments
 */
function extractInlineIgnores(content: string): Set<number> {
  const ignoredLines = new Set<number>();
  const lines = content.split('\n');
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Check if line contains an inline ignore comment
    if (INLINE_IGNORE_PATTERN.test(line)) {
      ignoredLines.add(i + 1); // Convert to 1-indexed line number
    }
  }
  
  return ignoredLines;
}

// Re-export for backwards compatibility
export { DANGEROUS_PATTERNS, patternStats };

export async function scanPatterns(repoPath: string): Promise<Issue[]> {
  const issues: Issue[] = [];
  
  // Load .redwoodignore patterns
  const ignoreConfig = await loadRedwoodIgnore(repoPath);
  const ignorePatterns = ignoreConfig?.patterns || [];
  
  const files = getFiles(repoPath, repoPath, ignorePatterns);
  
  for (const file of files) {
    const relPath = relative(repoPath, file);
    const ext = extname(file);
    
    try {
      const content = readFileSync(file, 'utf-8');
      
      // Extract inline ignore comments for this file
      const ignoredLines = extractInlineIgnores(content);
      
      for (const pattern of DANGEROUS_PATTERNS) {
        // Skip if pattern is for specific file types and this isn't one
        if (pattern.fileTypes && !pattern.fileTypes.includes(ext)) {
          continue;
        }
        
        let match;
        const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
        
        while ((match = regex.exec(content)) !== null) {
          const beforeMatch = content.slice(0, match.index);
          const lineNumber = beforeMatch.split('\n').length;
          
          // Skip if this line has an inline ignore comment
          if (ignoredLines.has(lineNumber)) {
            continue;
          }
          
          issues.push({
            id: `pattern-${issues.length + 1}`,
            type: pattern.name,
            severity: pattern.severity,
            file: relPath,
            line: lineNumber,
            message: pattern.message,
            match: match[0].slice(0, 50),
            fix: pattern.fix,
          });
        }
      }
    } catch (error) {
      // Skip files that can't be read
    }
  }
  
  return issues;
}

function getFiles(dir: string, repoPath: string, ignorePatterns: string[]): string[] {
  const files: string[] = [];
  
  try {
    const entries = readdirSync(dir);
    
    for (const entry of entries) {
      const fullPath = join(dir, entry);
      const relPath = relative(repoPath, fullPath);
      
      // Skip directories based on centralized defaults + .redwoodignore patterns
      if (DEFAULT_IGNORE_DIRS.includes(entry)) continue;
      if (ignorePatterns.length > 0 && shouldSkipDir(entry, fullPath, repoPath, ignorePatterns)) continue;
      
      // Allow important dotfiles for config scanning
      const allowedDotfiles = ['.env', '.env.local', '.env.example', '.env.production', '.env.development'];
      if (entry.startsWith('.') && !allowedDotfiles.includes(entry.toLowerCase())) continue;
      
      const stat = statSync(fullPath);
      
      if (stat.isDirectory()) {
        files.push(...getFiles(fullPath, repoPath, ignorePatterns));
      } else if (stat.isFile()) {
        // Skip if file matches ignore patterns
        if (ignorePatterns.length > 0 && isIgnored(fullPath, repoPath, ignorePatterns)) {
          continue;
        }
        
        const ext = extname(entry);
        const name = entry.toLowerCase();
        // Scan code files
        if (['.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.go', '.rs', '.java', '.mjs', '.php', '.c', '.cpp', '.h', '.cs'].includes(ext)) {
          files.push(fullPath);
        }
        // Scan config files and templates
        else if (['.yml', '.yaml', '.toml', '.json', '.ini', '.env', '.html', '.erb', '.ejs', '.twig', '.blade.php'].includes(ext)) {
          files.push(fullPath);
        }
        // Scan specific config files without extensions
        else if (['dockerfile', 'docker-compose.yml', 'docker-compose.yaml', '.env', '.env.local', '.env.example'].includes(name)) {
          files.push(fullPath);
        }
      }
    }
  } catch (error) {
    // Skip directories that can't be read
  }
  
  return files;
}
