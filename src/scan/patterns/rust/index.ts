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
	{
		name: "Rust command injection via std::process::Command",
		regex:
			/std::process::Command\s*::new\s*\([^)]*\).*?\.arg\s*\(\s*\w+\s*\+|\.arg\s*\(\s*format!\s*\(/g,
		severity: "critical",
		message: "Command execution with potentially user-controlled input enables command injection",
		fix: "Use arg() with individual string arguments instead of concatenation. Validate/whitelist all inputs before passing to Command",
		fileTypes: [".rs"],
	},
	{
		name: "Rust shell invocation via Command::new(sh)",
		regex: /Command::new\s*\(\s*["']sh["']\s*\)\s*\.arg\s*\(\s*["']-c["']\s*\)\s*\.arg\s*\(/g,
		severity: "critical",
		message:
			'Shell invocation with Command::new("sh").arg("-c").arg(input) allows command injection',
		fix: "Avoid invoking a shell. Use Command::new() directly with separate args, or validate/whitelist the input before passing to sh -c",
		fileTypes: [".rs"],
	},
	{
		name: "Rust shell command execution with set_shell",
		regex: /\.set_shell\s*\(\s*true\s*\)/g,
		severity: "critical",
		message: "Command executed with shell=true enables command injection attacks",
		fix: "Avoid using shell=true; pass arguments directly via arg() without shell interpretation",
		fileTypes: [".rs"],
	},
]);
