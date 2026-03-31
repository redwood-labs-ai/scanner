// Test file for inline bypass logging

// This should trigger eval pattern (no ignore)
eval("malicious code");

// This has ignore comment on the same line
eval("safe code"); // redwood-ignore: false positive in test file

// This has ignore comment - known vulnerability, will be fixed in v2.0
const config = require("/etc/passwd"); // redwood-ignore: legacy code, no longer used

// This should trigger without ignore
const secret = "hardcoded-api-key-12345";
