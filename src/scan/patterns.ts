import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative, extname } from 'path';
import type { Issue } from './engine.js';

interface Pattern {
  name: string;
  regex: RegExp;
  severity: Issue['severity'];
  message: string;
  fix: string;
  fileTypes?: string[];
}

const DANGEROUS_PATTERNS: Pattern[] = [
  // === RUST PATTERNS ===
  {
    name: 'Rust TLS verification disabled',
    regex: /danger_accept_invalid_certs\s*\(\s*true\s*\)|\.danger_accept_invalid_certs\s*\(\s*true\s*\)/g,
    severity: 'critical',
    message: 'TLS certificate verification is disabled, vulnerable to MITM attacks',
    fix: 'Remove danger_accept_invalid_certs(true) and use proper certificate validation',
    fileTypes: ['.rs'],
  },
  {
    name: 'Rust insecure TLS config',
    regex: /set_certificate_verifier\s*\(\s*Arc::new\s*\(\s*NoCertificateVerification|AcceptAnyServerCert|\.set_verify\s*\(\s*SslVerifyMode::NONE\s*\)/g,
    severity: 'critical',
    message: 'TLS certificate verification is disabled',
    fix: 'Use proper certificate verification',
    fileTypes: ['.rs'],
  },
  {
    name: 'Plaintext password comparison',
    regex: /password\s*==\s*|==\s*password|hash\s*==\s*|==\s*hash|verify_password.*==|==.*verify_password/gi,
    severity: 'critical',
    message: 'String comparison for passwords/hashes is vulnerable to timing attacks',
    fix: 'Use constant-time comparison functions like subtle::ConstantTimeEq or crypto secure_compare',
    fileTypes: ['.rs', '.py', '.js', '.ts', '.go'],
  },
  {
    name: 'Commented security middleware',
    regex: /\/\/\s*(rate.?limit|tower.?governor|throttle|brute.?force|auth.?guard|security|helmet)/gi,
    severity: 'medium',
    message: 'Security middleware appears to be commented out',
    fix: 'Uncomment and enable security middleware before deploying',
    fileTypes: ['.rs', '.js', '.ts', '.py'],
  },
  {
    name: 'Unwrap on security-sensitive code',
    regex: /\.unwrap\(\)|\.expect\s*\([^)]*\)/g,
    severity: 'low',
    message: 'Panicking on errors can cause denial of service',
    fix: 'Handle errors gracefully with proper error handling',
    fileTypes: ['.rs'],
  },
  // === JAVASCRIPT/TYPESCRIPT PATTERNS ===
  {
    name: 'eval() usage',
    regex: /\beval\s*\(/g,
    severity: 'high',
    message: 'eval() can execute arbitrary code and is a security risk',
    fix: 'Replace eval() with safer alternatives like JSON.parse() or a proper parser',
    fileTypes: ['.js', '.ts', '.jsx', '.tsx', '.mjs'],
  },
  {
    name: 'exec() usage',
    regex: /\bexec\s*\(/g,
    severity: 'high',
    message: 'exec() can execute arbitrary shell commands',
    fix: 'Use parameterized commands or escape user input properly',
    fileTypes: ['.js', '.ts', '.py'],
  },
  {
    name: 'child_process spawn with shell',
    regex: /spawn\s*\([^)]*shell\s*:\s*true/g,
    severity: 'high',
    message: 'Spawning with shell: true can lead to command injection',
    fix: 'Use spawn() without shell option and pass arguments as array',
    fileTypes: ['.js', '.ts'],
  },
  {
    name: 'SQL concatenation',
    // Match SQL strings followed by + concatenation (not + inside SQL which is arithmetic)
    regex: /["'`][\s\S]{0,50}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,50}["'`]\s*\+|\+\s*["'`][\s\S]{0,50}(SELECT|INSERT|UPDATE|DELETE)/gi,
    severity: 'critical',
    message: 'SQL string concatenation is vulnerable to SQL injection',
    fix: 'Use parameterized queries or an ORM',
  },
  {
    name: 'SQL f-string injection',
    regex: /f["'][\s\S]{0,20}(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)[\s\S]{0,50}\{/gi,
    severity: 'critical',
    message: 'SQL query built with f-string is vulnerable to injection',
    fix: 'Use parameterized queries with ? or %s placeholders',
    fileTypes: ['.py'],
  },
  {
    name: 'SQL format string injection',
    regex: /["'][\s\S]{0,20}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,50}["']\.format\s*\(/gi,
    severity: 'critical',
    message: 'SQL query built with .format() is vulnerable to injection',
    fix: 'Use parameterized queries with ? or %s placeholders',
    fileTypes: ['.py'],
  },
  {
    name: 'SQL template literal injection',
    regex: /`[\s\S]{0,20}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,50}\$\{/gi,
    severity: 'critical',
    message: 'SQL query built with template literal is vulnerable to injection',
    fix: 'Use parameterized queries with prepared statements',
    fileTypes: ['.js', '.ts'],
  },
  {
    name: 'SSTI via render_template_string',
    regex: /render_template_string\s*\(/g,
    severity: 'high',
    message: 'render_template_string is dangerous - ensure no user input reaches it',
    fix: 'Use render_template with static template files instead',
    fileTypes: ['.py'],
  },
  {
    name: 'SSTI via Jinja2 from_string',
    regex: /\.from_string\s*\(/g,
    severity: 'high',
    message: 'Jinja2 from_string is dangerous - ensure no user input reaches it',
    fix: 'Use static templates loaded from files instead',
    fileTypes: ['.py'],
  },
  {
    name: 'SSTI via Template() direct',
    regex: /\bTemplate\s*\(\s*[^"'][^)]/g,
    severity: 'high',
    message: 'Template() with variable input may be vulnerable to SSTI',
    fix: 'Use static templates; never pass user input to Template constructor',
    fileTypes: ['.py'],
  },
  {
    name: 'Insecure deserialization (pickle)',
    regex: /pickle\.loads?\s*\(|yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.Loader|yaml\.unsafe_load/g,
    severity: 'critical',
    message: 'Deserializing untrusted data can lead to remote code execution',
    fix: 'Use yaml.safe_load() or json instead of pickle/unsafe yaml',
    fileTypes: ['.py'],
  },
  {
    name: 'Command injection via os/subprocess',
    regex: /os\.system\s*\(|os\.popen\s*\(|subprocess\.call\s*\([^)]*shell\s*=\s*True|subprocess\.Popen\s*\([^)]*shell\s*=\s*True/g,
    severity: 'critical',
    message: 'Shell command execution with potential user input',
    fix: 'Use subprocess with shell=False and pass args as list',
    fileTypes: ['.py'],
  },
  // === SSRF PATTERNS ===
  {
    name: 'SSRF via urllib',
    regex: /urllib\.request\.urlopen\s*\(|urllib2\.urlopen\s*\(|urllib\.urlopen\s*\(/g,
    severity: 'high',
    message: 'URL fetching function may be vulnerable to SSRF if URL is user-controlled',
    fix: 'Validate and whitelist allowed URL schemes and hosts',
    fileTypes: ['.py'],
  },
  {
    name: 'SSRF via requests library',
    regex: /requests\.(get|post|put|delete|head|patch)\s*\([^)]*\+|requests\.(get|post|put|delete|head|patch)\s*\(.*\{/g,
    severity: 'high',
    message: 'HTTP request with potentially user-controlled URL',
    fix: 'Validate and whitelist allowed URL schemes and hosts',
    fileTypes: ['.py'],
  },
  {
    name: 'SSRF via fetch',
    regex: /fetch\s*\(\s*[^"'`][^)]*\)|fetch\s*\(\s*`[^`]*\$\{/g,
    severity: 'high',
    message: 'Fetch with potentially user-controlled URL',
    fix: 'Validate and whitelist allowed URL schemes and hosts',
    fileTypes: ['.js', '.ts'],
  },
  {
    name: 'SSRF via curl/file_get_contents',
    regex: /file_get_contents\s*\(\s*\$|curl_setopt\s*\([^)]*CURLOPT_URL[^)]*\$/g,
    severity: 'high',
    message: 'URL fetching with potentially user-controlled input',
    fix: 'Validate and whitelist allowed URL schemes and hosts',
    fileTypes: ['.php'],
  },
  // === PATH TRAVERSAL ===
  {
    name: 'Path traversal via open()',
    regex: /open\s*\([^)]*\+|open\s*\(.*\{|open\s*\(\s*f["']/g,
    severity: 'high',
    message: 'File open with potentially user-controlled path',
    fix: 'Use os.path.basename() or validate path does not contain ..',
    fileTypes: ['.py'],
  },
  {
    name: 'Path traversal via file read',
    regex: /readFileSync\s*\([^"'`]|readFile\s*\([^"'`]|fs\.(read|write)[^(]*\([^"'`]/g,
    severity: 'high',
    message: 'File operation with potentially user-controlled path',
    fix: 'Validate path and use path.resolve() to prevent directory traversal',
    fileTypes: ['.js', '.ts'],
  },
  {
    name: 'Path traversal via include/require',
    regex: /include\s*\(\s*\$|require\s*\(\s*\$|include_once\s*\(\s*\$|require_once\s*\(\s*\$/g,
    severity: 'critical',
    message: 'PHP include with user-controlled path enables LFI/RFI',
    fix: 'Use whitelist of allowed files, never include user input directly',
    fileTypes: ['.php'],
  },
  // === XXE ===
  {
    name: 'XXE via XML parsing',
    regex: /XMLParser\s*\(|xml\.etree\.ElementTree\.parse|lxml\.etree\.parse|xml\.dom\.minidom\.parse/g,
    severity: 'high',
    message: 'XML parsing may be vulnerable to XXE if external entities not disabled',
    fix: 'Disable external entity processing in XML parser',
    fileTypes: ['.py'],
  },
  {
    name: 'XXE via DOMParser',
    regex: /DOMParser\s*\(\s*\)|\.parseFromString\s*\(/g,
    severity: 'medium',
    message: 'XML parsing - ensure external entities are disabled',
    fix: 'Use JSON instead of XML, or disable external entity processing',
    fileTypes: ['.js', '.ts'],
  },
  // === FILE UPLOAD ===
  {
    name: 'Unrestricted file upload (PHP)',
    regex: /move_uploaded_file\s*\(/g,
    severity: 'high',
    message: 'File upload without visible type validation may allow malicious uploads',
    fix: 'Validate file extension, MIME type, and content; store outside webroot',
    fileTypes: ['.php'],
  },
  // === HARDCODED CREDENTIALS ===
  {
    name: 'Base64 encoded credentials',
    regex: /base64[._-]?decode\s*\([^)]*['"]\s*[A-Za-z0-9+/=]{16,}['"]/gi,
    severity: 'high',
    message: 'Potentially hardcoded credentials encoded in base64',
    fix: 'Use environment variables or secrets management for credentials',
    fileTypes: ['.py', '.js', '.ts', '.rb', '.go', '.php'],
  },
  {
    name: 'Base64 decode for password',
    regex: /password\s*=\s*[^;]*atob\s*\(|password\s*=\s*[^;]*base64\.decode\s*\(|password\s*=\s*Buffer\.from\s*\([^,]*,\s*['"]base64['"]\)/gi,
    severity: 'critical',
    message: 'Password retrieved via base64 decode - likely hardcoded credentials',
    fix: 'Use environment variables or secrets management for credentials',
    fileTypes: ['.py', '.js', '.ts', '.rb', '.go', '.php'],
  },
  {
    name: 'Hardcoded SSH/database connection',
    regex: /(ssh|paramiko|mysql|postgres|redis)\.connect\s*\([^)]*password\s*=\s*['"]/gi,
    severity: 'critical',
    message: 'Hardcoded credentials in connection string',
    fix: 'Use environment variables or secrets management',
    fileTypes: ['.py'],
  },
  // === MASS ASSIGNMENT / HIDDEN FIELDS ===
  {
    name: 'Hidden admin/role field',
    regex: /type\s*=\s*["']hidden["'][^>]*(admin|role|privilege|permission|is_?admin|is_?super)/gi,
    severity: 'high',
    message: 'Hidden form field controlling access - vulnerable to tampering',
    fix: 'Never trust client-side hidden fields for authorization; validate server-side',
    fileTypes: ['.html', '.php', '.erb', '.ejs', '.jsx', '.tsx'],
  },
  // === JWT ISSUES ===
  {
    name: 'JWT none algorithm',
    regex: /algorithm\s*[=:]\s*["']none["']|alg["']?\s*:\s*["']none["']/gi,
    severity: 'critical',
    message: 'JWT with "none" algorithm allows signature bypass',
    fix: 'Always specify and validate a secure algorithm (RS256, ES256)',
    fileTypes: ['.py', '.js', '.ts', '.rb', '.go'],
  },
  {
    name: 'JWT weak secret',
    regex: /jwt\.(encode|sign|decode|verify)\s*\([^)]*["'](secret|password|key|123|test|dev)["']/gi,
    severity: 'high',
    message: 'JWT using weak or hardcoded secret',
    fix: 'Use strong, randomly generated secrets from environment variables',
    fileTypes: ['.py', '.js', '.ts'],
  },
  // === GO PATTERNS ===
  {
    name: 'Go SQL injection',
    regex: /\.(Query|QueryRow|Exec)\s*\(\s*["'`].*\+|fmt\.Sprintf\s*\(\s*["'`].*SELECT|fmt\.Sprintf\s*\(\s*["'`].*INSERT|fmt\.Sprintf\s*\(\s*["'`].*UPDATE|fmt\.Sprintf\s*\(\s*["'`].*DELETE/gi,
    severity: 'critical',
    message: 'SQL query built with string concatenation/formatting',
    fix: 'Use parameterized queries with ? or $1 placeholders',
    fileTypes: ['.go'],
  },
  {
    name: 'Go command injection',
    regex: /exec\.Command\s*\(\s*["'][^"']*["']\s*\+|exec\.Command\s*\([^)]*fmt\.Sprintf/g,
    severity: 'critical',
    message: 'Command execution with potentially user-controlled input',
    fix: 'Validate and sanitize input, avoid shell execution',
    fileTypes: ['.go'],
  },
  {
    name: 'Go TLS skip verify',
    regex: /InsecureSkipVerify\s*:\s*true/g,
    severity: 'high',
    message: 'TLS certificate verification disabled',
    fix: 'Remove InsecureSkipVerify or set to false',
    fileTypes: ['.go'],
  },
  {
    name: 'Go unsafe package',
    regex: /import\s+["']unsafe["']|unsafe\.Pointer/g,
    severity: 'medium',
    message: 'Unsafe package usage bypasses Go memory safety',
    fix: 'Avoid unsafe unless absolutely necessary; document why',
    fileTypes: ['.go'],
  },
  {
    name: 'Go hardcoded credentials',
    regex: /(password|secret|apikey|api_key|token)\s*[:=]\s*["'][^"']{8,}["']/gi,
    severity: 'high',
    message: 'Potential hardcoded credentials',
    fix: 'Use environment variables or secrets management',
    fileTypes: ['.go'],
  },
  {
    name: 'Go path traversal',
    regex: /filepath\.Join\s*\([^)]*\+|os\.(Open|ReadFile|WriteFile)\s*\([^)]*\+/g,
    severity: 'high',
    message: 'File path with user-controlled input may allow traversal',
    fix: 'Use filepath.Clean and validate path does not escape base directory',
    fileTypes: ['.go'],
  },
  {
    name: 'Go SSRF',
    regex: /http\.(Get|Post|Head)\s*\([^"'`]|http\.NewRequest\s*\([^)]*\+/g,
    severity: 'high',
    message: 'HTTP request with potentially user-controlled URL',
    fix: 'Validate and whitelist allowed URL schemes and hosts',
    fileTypes: ['.go'],
  },
  // === RUBY PATTERNS ===
  {
    name: 'Ruby command injection',
    regex: /system\s*\(|exec\s*\(|`[^`]*#\{|%x\{|Open3\.(capture|popen)/g,
    severity: 'critical',
    message: 'Command execution that may include user input',
    fix: 'Use array form of system/exec to avoid shell interpolation',
    fileTypes: ['.rb', '.erb'],
  },
  {
    name: 'Ruby eval injection',
    regex: /\beval\s*\(|instance_eval|class_eval|module_eval/g,
    severity: 'critical',
    message: 'Dynamic code evaluation is dangerous with user input',
    fix: 'Avoid eval; use safer alternatives like case/when or method dispatch',
    fileTypes: ['.rb', '.erb'],
  },
  {
    name: 'Ruby send injection',
    regex: /\.send\s*\(|\.public_send\s*\(|\.try\s*\(/g,
    severity: 'high',
    message: 'Dynamic method invocation may allow arbitrary method calls',
    fix: 'Whitelist allowed method names before using send',
    fileTypes: ['.rb', '.erb'],
  },
  {
    name: 'Ruby YAML deserialization',
    regex: /YAML\.load\s*\(|Psych\.load\s*\(/g,
    severity: 'critical',
    message: 'YAML.load can execute arbitrary code via deserialization',
    fix: 'Use YAML.safe_load instead of YAML.load',
    fileTypes: ['.rb'],
  },
  {
    name: 'Ruby SQL injection',
    regex: /\.where\s*\(\s*["'][^"']*#\{|\.find_by_sql\s*\(\s*["'][^"']*#\{|\.execute\s*\(\s*["'][^"']*#\{/g,
    severity: 'critical',
    message: 'SQL query with string interpolation is vulnerable to injection',
    fix: 'Use parameterized queries: where("col = ?", value)',
    fileTypes: ['.rb'],
  },
  {
    name: 'Ruby ERB injection',
    regex: /ERB\.new\s*\(|render\s+inline\s*:/g,
    severity: 'high',
    message: 'Dynamic ERB rendering may allow template injection',
    fix: 'Use static templates; never pass user input to ERB.new',
    fileTypes: ['.rb'],
  },
  {
    name: 'Ruby open() command injection',
    regex: /\bopen\s*\(\s*["']\||\bopen\s*\([^)]*#\{[^}]*\}/g,
    severity: 'critical',
    message: 'Ruby open() with pipe or interpolation allows command execution',
    fix: 'Use File.open for files; avoid pipe syntax with user input',
    fileTypes: ['.rb'],
  },
  {
    name: 'Ruby mass assignment',
    regex: /attr_accessible|attr_protected|permit!|params\.(permit|require)\s*\([^)]*\)/g,
    severity: 'medium',
    message: 'Check mass assignment protection is correctly configured',
    fix: 'Use strong parameters; whitelist only needed attributes',
    fileTypes: ['.rb'],
  },
  {
    name: 'dangerouslySetInnerHTML',
    regex: /dangerouslySetInnerHTML\s*=\s*\{/g,
    severity: 'medium',
    message: 'dangerouslySetInnerHTML can lead to XSS if content is not sanitized',
    fix: 'Ensure content is sanitized or use a library like DOMPurify',
    fileTypes: ['.js', '.jsx', '.tsx'],
  },
  {
    name: 'Disabled SSL verification',
    regex: /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true/g,
    severity: 'high',
    message: 'Disabled SSL verification makes connections vulnerable to MITM attacks',
    fix: 'Enable SSL verification and use proper certificates',
  },
  {
    name: 'Hardcoded localhost/127.0.0.1 in production code',
    regex: /['"]https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?['"]/g,
    severity: 'low',
    message: 'Hardcoded localhost URLs may cause issues in production',
    fix: 'Use environment variables for URLs',
  },
  {
    name: 'CORS wildcard',
    regex: /['"]Access-Control-Allow-Origin['"]\s*[,:]\s*['"]\*['"]/gi,
    severity: 'medium',
    message: 'CORS wildcard (*) allows any origin to access this resource',
    fix: 'Restrict CORS to specific trusted origins',
  },
  {
    name: 'Debug mode enabled',
    regex: /DEBUG\s*=\s*True|debug\s*:\s*true|NODE_ENV\s*[!=]==?\s*['"]development['"]/gi,
    severity: 'low',
    message: 'Debug mode may be enabled - ensure this is not deployed to production',
    fix: 'Use environment variables to control debug mode',
  },
  {
    name: 'Weak crypto algorithm',
    regex: /createHash\s*\(\s*['"]md5['"]\)|createHash\s*\(\s*['"]sha1['"]\)/gi,
    severity: 'medium',
    message: 'MD5 and SHA1 are weak hashing algorithms',
    fix: 'Use SHA256 or stronger algorithms',
    fileTypes: ['.js', '.ts'],
  },
  {
    name: 'Math.random for security',
    regex: /Math\.random\s*\(\s*\)/g,
    severity: 'medium',
    message: 'Math.random() is not cryptographically secure',
    fix: 'Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive random values',
    fileTypes: ['.js', '.ts'],
  },
  // === CONFIG FILE PATTERNS ===
  {
    name: 'Default password in config',
    regex: /(password|passwd|pwd|secret|token)\s*[:=]\s*['"]?(secret|password|admin|root|123456|changeme|default|test|example)['"]/gi,
    severity: 'critical',
    message: 'Default/weak password found in configuration',
    fix: 'Use strong, unique passwords from environment variables',
    fileTypes: ['.yml', '.yaml', '.env', '.toml', '.json', '.ini'],
  },
  {
    name: 'Insecure shell default in env var',
    regex: /\$\{[A-Z_]*(PASSWORD|SECRET|TOKEN|KEY)[A-Z_]*:-(secret|password|admin|root|123456|changeme|default|test|example)[^}]*\}/gi,
    severity: 'critical',
    message: 'Insecure default value for sensitive environment variable',
    fix: 'Remove default values for secrets or use secure defaults',
    fileTypes: ['.yml', '.yaml', '.env', '.sh'],
  },
  {
    name: 'Hardcoded database credentials',
    regex: /(DATABASE_URL|POSTGRES_PASSWORD|MYSQL_PASSWORD|REDIS_PASSWORD|MONGO_URI)\s*[:=]\s*['"]?[^${\s][^'"}\s]+['"]?/gi,
    severity: 'high',
    message: 'Database credentials appear to be hardcoded',
    fix: 'Use environment variables or secrets management for database credentials',
    fileTypes: ['.yml', '.yaml', '.env', '.toml', '.json'],
  },
  {
    name: 'Exposed port 0.0.0.0',
    regex: /0\.0\.0\.0:\d+/g,
    severity: 'medium',
    message: 'Service bound to all interfaces (0.0.0.0) may be unintentionally exposed',
    fix: 'Consider binding to 127.0.0.1 for local-only services or restrict with firewall',
    fileTypes: ['.yml', '.yaml', '.toml', '.json'],
  },
  {
    name: 'Privileged container',
    regex: /privileged\s*:\s*true/gi,
    severity: 'high',
    message: 'Container running in privileged mode has excessive host access',
    fix: 'Remove privileged mode and use specific capabilities instead',
    fileTypes: ['.yml', '.yaml'],
  },
  {
    name: 'Host network mode',
    regex: /network_mode\s*:\s*['"]?host['"]?/gi,
    severity: 'medium',
    message: 'Container using host network mode bypasses network isolation',
    fix: 'Use bridge networking with explicit port mappings',
    fileTypes: ['.yml', '.yaml'],
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
      const lines = content.split('\n');
      
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
