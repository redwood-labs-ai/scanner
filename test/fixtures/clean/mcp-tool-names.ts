// FP baseline: MCP tool names that contain dangerous substrings
// but are actually safe compound names.

// These should NOT trigger "MCP: Dangerous Tool Name"
const tools = [
	// "system" substring - but these are safe system info tools
	{ name: "system_info", description: "Get system information" },
	{ name: "system_status", description: "Check system status" },
	{ name: "system_health", description: "Health check endpoint" },

	// "root" substring - directory/path tools
	{ name: "root_directory", description: "Get project root" },
	{ name: "root_path", description: "Resolve root path" },

	// "remove" substring - data management
	{ name: "remove_background", description: "Remove image background" },
	{ name: "remove_duplicates", description: "Deduplicate records" },
	{ name: "remove_item", description: "Remove item from list" },

	// "delete" substring - cache/data tools
	{ name: "delete_cache", description: "Clear cache entries" },
	{ name: "delete_expired", description: "Clean expired sessions" },

	// "admin" substring - info/panel tools
	{ name: "admin_panel_info", description: "Get admin panel config" },
	{ name: "database_admin", description: "Database admin status" },

	// "exec" substring - not standalone exec
	{ name: "get_executable", description: "Find executable path" },

	// "file" / "write" substrings
	{ name: "file_manager", description: "Manage file metadata" },
	{ name: "file_reader", description: "Read file contents safely" },
];

// MCP server indicator
const server = require("@modelcontextprotocol/sdk");
