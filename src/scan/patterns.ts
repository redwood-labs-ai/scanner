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

// Re-export for backwards compatibility
export { DANGEROUS_PATTERNS, patternStats };

const IGNORE_DIRS = [
  // JS/Node
  'node_modules', 'dist', 'build', '.next', '.nuxt', 
  // Rust
  'target', 
  // Python
  '__pycache__', '.venv', 'venv', 'env',
  // General
  '.git', 'vendor', 'third_party', 'deps',
  // Tests (configurable later)
  'test', 'tests', '__tests__', 'spec', 'fixtures',
];

export async function scanPatterns(repoPath: string): Promise<Issue[]> {
  const issues: Issue[] = [];
  const files = getFiles(repoPath);
  
  for (const file of files) {
    const relPath = relative(repoPath, file);
    const ext = extname(file);
    
    try {
      const content = readFileSync(file, 'utf-8');
      
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

function getFiles(dir: string): string[] {
  const files: string[] = [];
  
  try {
    const entries = readdirSync(dir);
    
    for (const entry of entries) {
      const fullPath = join(dir, entry);
      
      if (IGNORE_DIRS.includes(entry)) continue;
      // Allow important dotfiles for config scanning
      const allowedDotfiles = ['.env', '.env.local', '.env.example', '.env.production', '.env.development'];
      if (entry.startsWith('.') && !allowedDotfiles.includes(entry.toLowerCase())) continue;
      
      const stat = statSync(fullPath);
      
      if (stat.isDirectory()) {
        files.push(...getFiles(fullPath));
      } else if (stat.isFile()) {
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
