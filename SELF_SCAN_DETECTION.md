# Self-Scan Detection Heuristic

## Overview

When the Redwood Scanner scans its own codebase, it needs to detect and skip **pattern definition files** to avoid false positives. Pattern definition files contain regex patterns as string literals (e.g., `/eval\s*\(/g`) that would otherwise match the security patterns being defined.

## Implementation Location

- **File**: `src/scan/patterns.ts`
- **Function**: `isPatternDefinitionFile(content: string): boolean`

## Current Heuristic

The function uses string matching to detect pattern definition files:

```typescript
function isPatternDefinitionFile(content: string): boolean {
	// Check for common patterns in pattern definition files
	return (
		content.includes("definePatterns") ||
		content.includes("DANGEROUS_PATTERNS") ||
		/\bregex\s*:\s*[/`]/.test(content) ||
		content.includes("scan/patterns/")
	);
}
```

### Detection Criteria

1. **`definePatterns`** - Function name used to define security patterns
2. **`DANGEROUS_PATTERNS`** - Exported constant containing the patterns
3. **`regex : [/`]`** - Regex pattern with string literal (detected via regex)
4. **`scan/patterns/`** - Path indicator for pattern definition files

## Usage

The heuristic is used in the `scanPatterns()` function:

```typescript
for (const file of files) {
	const content = readFileSync(file, "utf-8");
	
	// Skip pattern definition files to avoid false positives
	if (isPatternDefinitionFile(content)) {
		continue;
	}
	
	// ... rest of scanning logic
}
```

## Potential Issues

### 1. False Positives (Over-Matching)

**Risk**: User code that happens to contain these strings could be incorrectly skipped.

**Examples**:
- A user has a function named `definePatterns` in their code (unlikely but possible)
- A user has a constant named `DANGEROUS_PATTERNS` (unlikely naming choice)
- A user has `scan/patterns/` in a comment or string literal

**Mitigation**: The combination of multiple checks makes false positives less likely. A file would need to match at least one criterion to be skipped.

### 2. False Negatives (Under-Matching)

**Risk**: New pattern definition files that don't match the heuristic could be scanned, causing the scanner to flag its own patterns.

**Examples**:
- Using a different function name like `registerPatterns` or `addPatterns`
- Storing patterns in a different variable name
- Using a different path structure

**Mitigation**: 
- Document this heuristic clearly (this document)
- Consider making the detection more robust (see Recommendations)

## Recommendations

### Short-Term

1. **Add a marker comment**: Require pattern definition files to include a specific comment like `// @redwood-pattern-definition` that can be detected more reliably
2. **File extension check**: Only apply this heuristic to files in specific directories (e.g., `src/scan/patterns/`)
3. **File path check**: Skip files whose paths match `**/scan/patterns/**/*.ts`

### Long-Term

1. **Configuration-based detection**: Allow users to configure which files are pattern definition files via a config file
2. **Signature-based detection**: Use a more sophisticated signature (e.g., specific export pattern, module structure)
3. **Whitelist approach**: Maintain an explicit list of known pattern definition files instead of heuristic detection

## Testing

To verify the heuristic works correctly:

1. **Self-scan test**: Run the scanner on its own codebase and verify pattern definition files are skipped
2. **False positive test**: Create test files with similar strings but should not be skipped
3. **False negative test**: Create pattern definition files that should be skipped but don't match current heuristic

## Related

- **RED-100**: Document self-scan detection heuristic (this task)
- **Pattern files**: Located in `src/scan/patterns/` by language
