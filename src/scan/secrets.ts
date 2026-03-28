import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative } from 'path';
import type { Issue } from './engine.js';

const SECRET_PATTERNS = [
  {
    name: 'AWS Access Key',
    regex: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical' as const,
  },
  {
    name: 'AWS Secret Key',
    // Must have context (aws/secret/key nearby) AND be exactly 40 chars base64
    // Excludes mangled symbols (start with _ or contain ::)
    regex: /(?<![A-Za-z0-9/+=_])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    severity: 'critical' as const,
    context: /aws.{0,20}secret|secret.{0,20}key|AWS_SECRET/i,
  },
  {
    name: 'OpenAI API Key',
    regex: /sk-[a-zA-Z0-9]{48,}/g,
    severity: 'critical' as const,
  },
  {
    name: 'Anthropic API Key',
    regex: /sk-ant-[a-zA-Z0-9-]{93,}/g,
    severity: 'critical' as const,
  },
  {
    name: 'GitHub Token',
    regex: /ghp_[a-zA-Z0-9]{36}/g,
    severity: 'critical' as const,
  },
  {
    name: 'GitHub OAuth',
    regex: /gho_[a-zA-Z0-9]{36}/g,
    severity: 'critical' as const,
  },
  {
    name: 'Stripe Secret Key',
    regex: /sk_live_[a-zA-Z0-9]{24,}/g,
    severity: 'critical' as const,
  },
  {
    name: 'Stripe Publishable Key (Live)',
    regex: /pk_live_[a-zA-Z0-9]{24,}/g,
    severity: 'medium' as const,
  },
  {
    name: 'Private Key',
    regex: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    severity: 'critical' as const,
  },
  {
    name: 'Generic API Key Assignment',
    regex: /(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,}['"]/gi,
    severity: 'high' as const,
  },
  {
    name: 'Password Assignment',
    regex: /(password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    severity: 'high' as const,
  },
  {
    name: 'Bearer Token',
    regex: /bearer\s+[a-zA-Z0-9_\-.]{20,}/gi,
    severity: 'high' as const,
  },
];

const IGNORE_DIRS = [
  // JS/Node
  'node_modules', 'dist', 'build', '.next', '.nuxt', 
  // Rust
  'target', 
  // Python
  '__pycache__', '.venv', 'venv', 'env',
  // General
  '.git', 'vendor', 'third_party', 'deps',
  // Tests
  'test', 'tests', '__tests__', 'spec', 'fixtures',
];
const IGNORE_EXTENSIONS = [
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

export async function scanSecrets(repoPath: string): Promise<Issue[]> {
  const issues: Issue[] = [];
  const files = getFiles(repoPath);
  
  for (const file of files) {
    const relPath = relative(repoPath, file);
    
    try {
      const content = readFileSync(file, 'utf-8');
      const lines = content.split('\n');
      
      for (const pattern of SECRET_PATTERNS) {
        let match;
        const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
        
        while ((match = regex.exec(content)) !== null) {
          // Find line number
          const beforeMatch = content.slice(0, match.index);
          const lineNumber = beforeMatch.split('\n').length;
          const line = lines[lineNumber - 1];
          
          // Skip if context requirement not met
          if (pattern.context && !pattern.context.test(line)) {
            continue;
          }
          
          // Mask the secret in output
          const masked = maskSecret(match[0]);
          
          issues.push({
            id: `secret-${issues.length + 1}`,
            type: pattern.name,
            severity: pattern.severity,
            file: relPath,
            line: lineNumber,
            message: `Found ${pattern.name}`,
            match: masked,
            fix: `Move this secret to an environment variable`,
          });
        }
      }
    } catch (error) {
      // Skip files that can't be read (binary, permissions, etc.)
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
      if (IGNORE_EXTENSIONS.some(ext => entry.endsWith(ext))) continue;
      
      const stat = statSync(fullPath);
      
      if (stat.isDirectory()) {
        files.push(...getFiles(fullPath));
      } else if (stat.isFile()) {
        files.push(fullPath);
      }
    }
  } catch (error) {
    // Skip directories that can't be read
  }
  
  return files;
}

function maskSecret(secret: string): string {
  if (secret.length <= 8) return '*'.repeat(secret.length);
  return secret.slice(0, 4) + '*'.repeat(secret.length - 8) + secret.slice(-4);
}
