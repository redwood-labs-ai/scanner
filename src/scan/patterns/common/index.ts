import { definePatterns } from "../types.js";

/**
 * Cross-language patterns that apply to multiple file types
 */
export default definePatterns([
	{
		name: "Plaintext password comparison",
		regex:
			/password\s*==\s*|==\s*password|hash\s*==\s*|==\s*hash|verify_password.*==|==.*verify_password/gi,
		severity: "critical",
		message: "String comparison for passwords/hashes is vulnerable to timing attacks",
		fix: "Use constant-time comparison functions like subtle::ConstantTimeEq or crypto secure_compare",
		fileTypes: [".rs", ".py", ".js", ".ts", ".go"],
	},
	{
		name: "Commented security middleware",
		regex:
			/\/\/\s*(rate.?limit|tower.?governor|throttle|brute.?force|auth.?guard|security|helmet)/gi,
		severity: "medium",
		message: "Security middleware appears to be commented out",
		fix: "Uncomment and enable security middleware before deploying",
		fileTypes: [".rs", ".js", ".ts", ".py"],
	},
	{
		name: "exec() usage",
		regex: /\bexec\s*\(/g,
		severity: "high",
		message: "exec() can execute arbitrary shell commands",
		fix: "Use parameterized commands or escape user input properly",
		fileTypes: [".js", ".ts", ".py"],
	},
	{
		name: "SQL concatenation",
		regex:
			/["'`][\s\S]{0,50}(SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,50}["'`]\s*\+|\+\s*["'`][\s\S]{0,50}(SELECT|INSERT|UPDATE|DELETE)/gi,
		severity: "critical",
		message: "SQL string concatenation is vulnerable to SQL injection",
		fix: "Use parameterized queries or an ORM",
	},
	{
		name: "Base64 encoded credentials",
		regex: /base64[._-]?decode\s*\([^)]*['"]\s*[A-Za-z0-9+/=]{16,}['"]/gi,
		severity: "high",
		message: "Potentially hardcoded credentials encoded in base64",
		fix: "Use environment variables or secrets management for credentials",
		fileTypes: [".py", ".js", ".ts", ".rb", ".go", ".php"],
	},
	{
		name: "Base64 decode for password",
		regex:
			/password\s*=\s*[^;]*atob\s*\(|password\s*=\s*[^;]*base64\.decode\s*\(|password\s*=\s*Buffer\.from\s*\([^,]*,\s*['"]base64['"]\)/gi,
		severity: "critical",
		message: "Password retrieved via base64 decode - likely hardcoded credentials",
		fix: "Use environment variables or secrets management for credentials",
		fileTypes: [".py", ".js", ".ts", ".rb", ".go", ".php"],
	},
	{
		name: "Hardcoded SSH/database connection",
		regex: /(ssh|paramiko|mysql|postgres|redis)\.connect\s*\([^)]*password\s*=\s*['"]/gi,
		severity: "critical",
		message: "Hardcoded credentials in connection string",
		fix: "Use environment variables or secrets management",
		fileTypes: [".py"],
	},
	{
		name: "Hidden admin/role field",
		regex: /type\s*=\s*["']hidden["'][^>]*(admin|role|privilege|permission|is_?admin|is_?super)/gi,
		severity: "high",
		message: "Hidden form field controlling access - vulnerable to tampering",
		fix: "Never trust client-side hidden fields for authorization; validate server-side",
		fileTypes: [".html", ".php", ".erb", ".ejs", ".jsx", ".tsx"],
	},
	{
		name: "JWT none algorithm",
		regex: /algorithm\s*[=:]\s*["']none["']|alg["']?\s*:\s*["']none["']/gi,
		severity: "critical",
		message: 'JWT with "none" algorithm allows signature bypass',
		fix: "Always specify and validate a secure algorithm (RS256, ES256)",
		fileTypes: [".py", ".js", ".ts", ".rb", ".go"],
	},
	{
		name: "JWT weak secret",
		regex: /jwt\.(encode|sign|decode|verify)\s*\([^)]*["'](secret|password|key|123|test|dev)["']/gi,
		severity: "high",
		message: "JWT using weak or hardcoded secret",
		fix: "Use strong, randomly generated secrets from environment variables",
		fileTypes: [".py", ".js", ".ts"],
	},
	{
		name: "Disabled SSL verification",
		regex: /rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true/g,
		severity: "high",
		message: "Disabled SSL verification makes connections vulnerable to MITM attacks",
		fix: "Enable SSL verification and use proper certificates",
	},
	{
		name: "Hardcoded localhost/127.0.0.1 in production code",
		regex: /['"]https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?['"]/g,
		severity: "low",
		message: "Hardcoded localhost URLs may cause issues in production",
		fix: "Use environment variables for URLs",
	},
	{
		name: "CORS wildcard",
		regex: /['"]Access-Control-Allow-Origin['"]\s*[,:]\s*['"]\*['"]/gi,
		severity: "medium",
		message: "CORS wildcard (*) allows any origin to access this resource",
		fix: "Restrict CORS to specific trusted origins",
	},
	{
		name: "Debug mode enabled",
		regex: /DEBUG\s*=\s*True|debug\s*:\s*true|NODE_ENV\s*[!=]==?\s*['"]development['"]/gi,
		severity: "low",
		message: "Debug mode may be enabled - ensure this is not deployed to production",
		fix: "Use environment variables to control debug mode",
	},
	{
		name: "Prototype pollution via convict (CVE-2026-33864)",
		regex:
			/convict\s*[(\s]|require\s*\(.*['"]convict['"]|from\s*['"]convict['"]|\.__proto__|constructor\s*\.\s*prototype|__defineGetter__|__lookupGetter__/gi,
		severity: "critical",
		message:
			"convict configuration with prototype pollution vectors. The startsWith() function and schema initialization may pollute Object.prototype, leading to privilege escalation or DoS",
		fix: "Upgrade convict to >=6.2.5. Sanitize configuration objects before passing to convict. Avoid configuration objects containing __proto__, constructor.prototype, or other prototype pollution vectors",
		fileTypes: [".js", ".ts", ".mjs"],
	},
	{
		name: "Prototype pollution via Object.assign",
		regex:
			/Object\.assign\s*\(.*\.\.\.|Object\.assign\s*\(undefined|Object\.assign\s*\(.*require\s*\(/gi,
		severity: "high",
		message:
			"Object.assign with untrusted source may cause prototype pollution if source contains __proto__ or constructor keys",
		fix: "Validate source objects and reject any containing __proto__, constructor, or prototype keys. Use Object.assign with sanitized inputs only",
		fileTypes: [".js", ".ts", ".mjs"],
	},
	{
		name: "Prototype pollution via spread operator",
		regex:
			/\{\s*\.\.\.JSON\.parse\s*\(|\{\s*\.\.\.req\.(body|query|params)\b|\{\s*\.\.\.(await\s+)?(fetch|axios|got|request)\s*\(/gi,
		severity: "high",
		message:
			"Spreading parsed JSON or request data directly may propagate prototype pollution. Attacker-controlled __proto__ or constructor keys in the source will pollute the new object",
		fix: "Sanitize objects before spreading: filter out __proto__, constructor, and prototype keys. Use a safe merge library or validate input schema before spreading",
		fileTypes: [".js", ".ts", ".mjs"],
	},
	{
		name: "AWS IMDS access (169.254.169.254)",
		regex: /169\.254\.169\.254|imds\.amazonaws\.com/gi,
		severity: "high",
		message:
			"Access to AWS Instance Metadata Service (IMDS) at 169.254.169.254. If used without IMDSv2 token requirements, this can lead to credential theft and AWS account compromise (as seen in Trivy supply chain attacks)",
		fix: "Use IMDSv2 with required session tokens (X-aws-ec2-metadata-token header). Restrict network access to IMDS endpoint. Ensure code doesn't fetch metadata from arbitrary sources",
		fileTypes: [".go", ".py", ".js", ".ts", ".java", ".rb"],
	},
	{
		name: "GCP metadata server access",
		regex:
			/metadata\.google\.internal|169\.254\.169\.254\/computeMetadata|googleapis\.com\/compute\/v1\/projects\/.*\/zones\/.*\/instances\/.*\/metadata/gi,
		severity: "high",
		message:
			"Access to Google Cloud Platform (GCP) metadata server. If used without proper authentication headers (Metadata-Flavor: Google), this can lead to service account credential theft",
		fix: "Use restricted service accounts with minimal permissions. Avoid accessing metadata server from untrusted code. Validate Metadata-Flavor header when making metadata requests",
		fileTypes: [".go", ".py", ".js", ".ts", ".java", ".rb"],
	},
	{
		name: "Azure instance metadata access",
		regex:
			/169\.254\.169\.254\/metadata\/instance|168\.63\.129\.16|azure\.com\/providers\/Microsoft\.Compute\/locations\/operations/gi,
		severity: "high",
		message:
			"Access to Azure Instance Metadata Service. Without the required Azure-Portal-Service header, this can expose managed identity credentials and lead to Azure resource compromise",
		fix: "Use managed identities with least privilege. Require Azure-Portal-Service header for metadata requests. Implement network security groups to restrict metadata access",
		fileTypes: [".go", ".py", ".js", ".ts", ".java", ".rb", ".cs"],
	},
	{
		name: "DigitalOcean droplet metadata access",
		regex: /169\.254\.169\.254\/metadata\/v1|metadata\.digitalocean\.com/gi,
		severity: "high",
		message:
			"Access to DigitalOcean droplet metadata service. Can expose droplet credentials, SSH keys, and other sensitive configuration",
		fix: "Use DigitalOcean App Platform or restricted metadata access. Implement firewall rules to block unauthorized metadata requests",
		fileTypes: [".go", ".py", ".js", ".ts", ".java", ".rb"],
	},
]);
