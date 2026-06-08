import * as fs from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const actionDir = path.join(root, "packages", "action");
const distDir = path.join(actionDir, "dist");
const rulesDir = path.join(root, "packages", "rules");

const actionPkg = JSON.parse(await fs.readFile(path.join(actionDir, "package.json"), "utf8"));
const corePkg = JSON.parse(await fs.readFile(path.join(root, "packages", "core", "package.json"), "utf8"));
const rulesPkg = JSON.parse(await fs.readFile(path.join(rulesDir, "package.json"), "utf8"));

await fs.rm(distDir, { recursive: true, force: true });
await fs.mkdir(path.join(distDir, "rules"), { recursive: true });
await fs.cp(path.join(rulesDir, "languages"), path.join(distDir, "rules", "languages"), { recursive: true });
await fs.writeFile(
  path.join(distDir, "rules", "package.json"),
  JSON.stringify({ name: rulesPkg.name, version: rulesPkg.version }, null, 2) + "\n",
  "utf8",
);

await fs.writeFile(
  path.join(actionDir, "src", "generated.ts"),
  [
    `export const ACTION_VERSION = ${JSON.stringify(actionPkg.version)};`,
    `export const BUNDLED_ENGINE_VERSION = ${JSON.stringify(corePkg.version)};`,
    `export const BUNDLED_RULES_VERSION = ${JSON.stringify(rulesPkg.version)};`,
    "",
  ].join("\n"),
  "utf8",
);
