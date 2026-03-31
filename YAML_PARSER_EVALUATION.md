# YAML Parser Evaluation for RED-101

## Overview
The config system in `src/scan/config.ts` includes a hand-rolled YAML parser (`parseYaml()` function) with "basic support for nested objects and arrays". This evaluation identifies edge case issues and potential problems.

## Current Implementation Summary

The `parseYaml()` function (lines 168-210) attempts to parse YAML with:
- Line-by-line parsing
- Basic key-value pair detection using colon separator
- Support for nested objects (when value is empty or `{`)
- Support for arrays (lines starting with `- `)
- Type parsing via `parseValue()` (boolean, number, null, string)

## Identified Issues and Edge Cases

### 1. **CRITICAL: No Indentation Tracking**
The parser does NOT track indentation levels, which is fundamental to YAML semantics.

**Problem Examples:**
```yaml
# This will fail - cannot distinguish nested levels
config:
  nested: value1
  another: value2
# Parser will treat 'nested' and 'another' as top-level keys
```

**Impact**: Any properly indented nested structure beyond one level will be parsed incorrectly.

### 2. **CRITICAL: Nested Object Detection is Broken**
```typescript
if (!value || value === "{") {
    currentKey = key;
    currentNested = {};
    result[key] = currentNested;
    nestedKey = key;
}
```

**Problem**: Once a nested object is detected, ALL subsequent keys are added to that one nested object until... what? There's no logic to exit the nested context when indentation decreases.

**Example that will fail:**
```yaml
scanners:
  secrets: true
  dependencies: false
output:
  verbose: true
```
The parser will incorrectly put `output` inside the `scanners` object.

### 3. **NO Support for Multi-line Strings**
YAML supports multi-line strings via `|` and `>` indicators. The parser will fail on:
```yaml
description: |
  This is a
  multi-line
  string value
```

### 4. **NO Support for Quoted Strings with Colons**
```yaml
path: "/home/user:documents/file.txt"
```
The parser will split on the first colon and fail.

### 5. **BROKEN Array Handling**
```typescript
if (trimmed.startsWith("- ") && currentNested && nestedKey) {
    const value = trimmed.slice(2).trim();
    if (!Array.isArray(currentNested[nestedKey])) {
        currentNested[nestedKey] = [];
    }
    (currentNested[nestedKey] as string[]).push(value);
}
```

**Problems:**
- Only works if array is inside a nested object (won't work for top-level arrays)
- Arrays are only stored as `string[]` - no type parsing for array items
- No support for nested arrays
- No support for array objects like `[- item1, - item2]`

### 6. **Limited Type Parsing**
The `parseValue()` function has issues:
- **No support for quoted numbers**: `value: "123"` will remain a string
- **No support for exponential notation**: `1e10` won't be parsed
- **No support for YAML tags**: `!!str`, `!!int`, etc.
- **No support for timestamps, dates, or complex types**
- **Edge case**: Empty string after colon `key:` returns `null` not empty string

### 7. **No Escaping Support**
```yaml
message: "Say \"Hello\""
path: C:\Users\name
```
No escape sequence handling - backslashes and quotes will cause issues.

### 8. **No Merge Key Support**
YAML `<<` merge key feature is not supported.

### 9. **No Anchor/Alias Support**
```yaml
default: &default
  verbose: false
config:
  <<: *default
  verbose: true
```
Not supported.

### 10. **No Flow Mapping/Sequence Support**
```yaml
config: {key: value, another: value2}
items: [item1, item2, item3]
```
The parser doesn't handle inline flow style.

### 11. **Unicode Issues**
No explicit Unicode handling - might fail on non-ASCII content.

### 12. **No Error Handling for Malformed YAML**
The parser silently continues on malformed input rather than throwing helpful errors.

### 13. **No Document Separator Support**
YAML supports multiple documents with `---` separator. Not supported.

### 14. **Trailing Content Issues**
```yaml
key: value
# Some trailing comment
garbage content here
```
The parser will try to parse "garbage content here" and likely fail or create nonsense output.

### 15. **Colons in Values (Unquoted)**
```yaml
time: 10:30
ratio: 1:100
```
Will be parsed incorrectly as nested objects.

## Test Results

Created comprehensive test suite in `tests/config-yaml-parser.test.ts` demonstrating failures:

### Test Failure Summary
- ✅ Simple flat config: **PASSES** (only trivial cases work)
- ❌ Multiple keys in nested object: **FAILS** (second key added to wrong level)
- ❌ Multiple nested sections: **FAILS** (later sections absorbed into previous)
- ❌ Top-level arrays: **FAILS** (completely broken, returns undefined)
- ❌ Real .redwoodrc.yaml.example: **FAILS** (catastrophic parsing errors)

### Actual vs Expected for Real Config

**Input** (`.redwoodrc.yaml.example`):
```yaml
severity: high
ignore:
  - '**/node_modules/**'
scanners:
  secrets: true
output:
  verbose: false
```

**Expected Output**:
```json
{
  "severity": "high",
  "ignore": ["**/node_modules/**"],
  "scanners": {"secrets": true},
  "output": {"verbose": false}
}
```

**Actual Output** (from parser):
```json
{
  "severity": "high",
  "ignore": {
    "ignore": ["'**/node_modules/**'"],
    "scanners": null,
    "secrets": true,
    "output": null,
    "verbose": false
  }
}
```

**Problems in Actual Output**:
1. `ignore` is an object instead of array
2. `scanners` and `output` sections absorbed into `ignore`
3. Array items quoted when they shouldn't be
4. Top-level `output` key completely missing
5. Nested structure completely corrupted


### Test Case 1: Deep Nesting
```yaml
level1:
  level2:
    level3: value
```
**Expected**: `{level1: {level2: {level3: "value"}}}`
**Actual**: Will likely put `level3` at wrong level or fail

### Test Case 2: Mixed Nesting
```yaml
config:
  scanners:
    secrets: true
  output:
    verbose: true
```
**Expected**: Properly nested structure
**Actual**: `output` will likely be added to `scanners` object

### Test Case 3: Top-level Array
```yaml
ignore:
  - node_modules
  - dist
```
**Expected**: `{ignore: ["node_modules", "dist"]}`
**Actual**: Will fail because `currentNested` is null at top level

### Test Case 4: Colon in Value
```yaml
path: "/path/to:file"
```
**Expected**: `{path: "/path/to:file"}`
**Actual**: Will split on colon and create nested object

### Test Case 5: Boolean in Array
```yaml
features:
  - enabled: true
  - enabled: false
```
**Expected**: Array of objects
**Actual**: Will fail - doesn't support array of objects

## Recommendations

### Short-Term (If Keeping Hand-Rolled Parser)

1. **Add indentation tracking** - Track current indentation level and adjust context accordingly
2. **Fix nested object exit logic** - Detect when indentation decreases to exit nested context
3. **Support top-level arrays** - Don't require `currentNested` for array items
4. **Type-parsing for arrays** - Apply `parseValue()` to array items
5. **Better error handling** - Throw descriptive errors on malformed input
6. **Quote handling** - Properly handle quoted strings that contain colons
7. **Add comprehensive tests** - Test all edge cases

### Long-Term (RECOMMENDED)

**Replace with a proper YAML library:**

Options:
1. **`js-yaml`** - Most popular, full YAML 1.1/1.2 support
   - Pros: Mature, well-tested, full YAML spec compliance
   - Cons: ~150KB bundle size
   
2. **`yaml`** - Modern YAML 1.2 parser
   - Pros: Actively maintained, good error messages
   - Cons: ~80KB bundle size

3. **`js-yaml` with tree-shaking** - Use only the parse function
   - Pros: Smaller footprint, still robust
   - Cons: Still adds dependency

**Given this is a config parser (not performance-critical), the dependency size is negligible compared to correctness and maintenance burden.**

## Risk Assessment

| Issue | Severity | Likelihood | Impact |
|-------|----------|8/10|8/10|
| No indentation tracking | Critical | Certain | Complete parsing failure for nested configs |
| Broken nested object exit | Critical | Certain | Corrupted config structure |
| No top-level arrays | High | Very Likely | `ignore: [...]` won't work |
| No type parsing in arrays | Medium | Very Likely | Array items always strings |
| Colon in unquoted values | High | Likely | User configs will fail unexpectedly |
| No multi-line strings | Medium | Possible | Limits config flexibility |
| No proper error messages | Medium | Certain | Hard to debug config issues |

## Conclusion

**The current hand-rolled YAML parser is fundamentally broken for any real-world config file beyond the simplest flat structures.**

The parser lacks:
- Indentation tracking (YAML's core feature)
- Proper nested object context management
- Top-level array support
- Robust type parsing
- Error handling

**TEST RESULTS CONFIRMED**: Created comprehensive test suite in `tests/config-yaml-parser.test.ts` which demonstrates:
- ✅ Only trivial flat configs work (single key-value pairs)
- ❌ Multiple keys in nested object: FAILS (second key added to wrong level)
- ❌ Multiple nested sections: FAILS (later sections absorbed into previous)
- ❌ Top-level arrays: FAILS (returns undefined/null)
- ❌ Real `.redwoodrc.yaml.example`: FAILS (catastrophic parsing, produces garbage output)

The actual parsing of the example config produces completely corrupted output where all nested content is merged into the first detected object, making the config unusable.

**Recommendation: Replace with a proven YAML library immediately.**


If time/resources are constrained, the minimum viable fix would require:
1. Complete rewrite with indentation tracking
2. Proper context stack for nesting
3. Comprehensive test suite

Given the narrow use case (config files), adding `js-yaml` or `yaml` package is the safest, most maintainable solution.

## Next Steps

1. **Decision needed**: Keep hand-rolled parser (rewrite needed) vs. add dependency
2. If keeping: Create comprehensive test suite first to capture current behavior
3. If adding dependency: Evaluate bundle size impact and add `js-yaml`
4. Add migration guide for users if parser behavior changes
