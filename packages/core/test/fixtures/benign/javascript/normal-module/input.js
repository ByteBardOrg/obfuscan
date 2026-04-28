// A normal CommonJS module; nothing dynamic, no decoders, no network sinks.
const fs = require("fs");
const path = require("path");

function readConfig(dir) {
  const p = path.join(dir, "config.json");
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

module.exports = { readConfig };
