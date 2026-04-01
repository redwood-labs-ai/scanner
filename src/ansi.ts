/**
 * Simple ANSI color helper to replace chalk dependency
 */

const codes = {
	reset: 0,
	bold: 1,
	dim: 2,
	red: 31,
	green: 32,
	yellow: 33,
	cyan: 36,
} as const;

function colorize(text: string, code: number): string {
	return `\u001b[${code}m${text}\u001b[0m`;
}

export const ansi = {
	reset: (text: string) => colorize(text, codes.reset),
	bold: (text: string) => colorize(text, codes.bold),
	dim: (text: string) => colorize(text, codes.dim),
	red: (text: string) => colorize(text, codes.red),
	green: (text: string) => colorize(text, codes.green),
	yellow: (text: string) => colorize(text, codes.yellow),
	cyan: (text: string) => colorize(text, codes.cyan),
};
