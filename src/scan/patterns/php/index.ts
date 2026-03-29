import { definePatterns } from '../types.js';

export default definePatterns([
  {
    name: 'SSRF via curl/file_get_contents',
    regex: /file_get_contents\s*\(\s*\$|curl_setopt\s*\([^)]*CURLOPT_URL[^)]*\$/g,
    severity: 'high',
    message: 'URL fetching with potentially user-controlled input',
    fix: 'Validate and whitelist allowed URL schemes and hosts',
    fileTypes: ['.php'],
  },
  {
    name: 'Path traversal via include/require',
    regex: /include\s*\(\s*\$|require\s*\(\s*\$|include_once\s*\(\s*\$|require_once\s*\(\s*\$/g,
    severity: 'critical',
    message: 'PHP include with user-controlled path enables LFI/RFI',
    fix: 'Use whitelist of allowed files, never include user input directly',
    fileTypes: ['.php'],
  },
  {
    name: 'Unrestricted file upload (PHP)',
    regex: /move_uploaded_file\s*\(/g,
    severity: 'high',
    message: 'File upload without visible type validation may allow malicious uploads',
    fix: 'Validate file extension, MIME type, and content; store outside webroot',
    fileTypes: ['.php'],
  },
]);
