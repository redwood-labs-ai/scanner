# RED-102: Glob Migration Investigation

## Task
Verify glob 10→13 migration has no breaking changes

## Investigation Date
2026-03-30

## Findings

### Current State
- **glob version**: 13.0.6 (installed)
- **Node requirement**: >=18 (package.json)
- **Usage in codebase**: NONE - glob is not imported anywhere in source files

### Key Discovery
The `glob` package is listed as a dependency in `package.json` but is **NOT actually used** in the source code:
- No `import { glob } from 'glob'` found in src/
- No `from 'glob'` imports found in any TypeScript/JavaScript files
- The `src/scan/ignore.ts` file has its own custom `matchesGlob()` function using regex-based pattern matching

### Glob v10 → v13 Breaking Changes (from official changelog)

#### v11.0 Breaking Changes
- **Dropped support for Node < v20** - This could be a concern if we need to support Node 18
- Promise API instead of callbacks
- Exported function names changed

#### v12.0 Breaking Changes
- Removed the unsafe `--shell` option

#### v13.0 Breaking Changes
- Moved CLI program out to separate package `glob-bin`

### Impact Assessment
**NO BREAKING CHANGES** - Since glob is not used in our codebase, the migration from v10 to v13 has no functional impact on the application.

### Recommendations

1. **Remove unused dependency**: Consider removing `glob` from `package.json` dependencies since it's not used
2. **Verify Node version requirement**: Current requirement is `>=18` but glob v11+ requires `>=20`. Since we don't use glob, this is not a concern unless we plan to use it
3. **Keep custom implementation**: The `matchesGlob()` function in `src/scan/ignore.ts` provides sufficient functionality for gitignore-style pattern matching

### Conclusion
The glob migration from v10 to v13 is **safe** and has **no breaking changes** for this codebase because the glob package is not actively used.
