import { copyFile } from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.resolve(here, "..");
const repoRoot = path.resolve(packageDir, "..", "..");

async function main() {
  await copyFile(path.join(repoRoot, "README.md"), path.join(packageDir, "README.md"));
  await copyFile(path.join(repoRoot, "LICENSE"), path.join(packageDir, "LICENSE"));
}

main().catch((error) => {
  console.error("Failed to sync root README/LICENSE into packages/core", error);
  process.exit(1);
});
