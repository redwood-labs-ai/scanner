// FP baseline: File operations with safe paths
// These use __dirname, path.join, path.resolve etc. and should NOT
// trigger "Path traversal via file read" because the path isn't
// user-controlled.

import { readFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

// Safe: __dirname-based paths
const config = readFileSync(__dirname + "/config.json", "utf-8");
const schema = readFileSync(__dirname + "/schema.sql", "utf-8");

// Safe: path.join with __dirname
const data = readFileSync(join(__dirname, "data.json"));
const template = readFileSync(join(__dirname, "..", "templates", "default.html"));

// Safe: path.resolve with constants
const manifest = readFileSync(resolve(process.cwd(), "manifest.json"));
const settings = readFileSync(resolve(import.meta.dirname, "settings.yaml"));

// Safe: path.normalize
const content = readFileSync(join(__dirname, path.normalize("../lib/index.js")));
