import { definePatterns } from "../types.js";

export default definePatterns([
	{
		name: "Rust TLS verification disabled",
		regex:
			/danger_accept_invalid_certs\s*\(\s*true\s*\)|\.danger_accept_invalid_certs\s*\(\s*true\s*\)/g,
		severity: "critical",
		message: "TLS certificate verification is disabled, vulnerable to MITM attacks",
		fix: "Remove danger_accept_invalid_certs(true) and use proper certificate validation",
		fileTypes: [".rs"],
	},
	{
		name: "Rust insecure TLS config",
		regex:
			/set_certificate_verifier\s*\(\s*Arc::new\s*\(\s*NoCertificateVerification|AcceptAnyServerCert|\.set_verify\s*\(\s*SslVerifyMode::NONE\s*\)/g,
		severity: "critical",
		message: "TLS certificate verification is disabled",
		fix: "Use proper certificate verification",
		fileTypes: [".rs"],
	},
	{
		name: "Unwrap on security-sensitive code",
		regex: /\.unwrap\(\)|\.expect\s*\([^)]*\)/g,
		severity: "low",
		message: "Panicking on errors can cause denial of service",
		fix: "Handle errors gracefully with proper error handling",
		fileTypes: [".rs"],
	},
]);
