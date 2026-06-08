import type { Severity } from "@obfuscan/core";

export type FailOn = "block" | "warn" | "never";

export interface ActionInputs {
  githubToken: string;
  failOn: FailOn;
  minSeverity: Severity;
  comment: boolean;
  maxFindings: number;
  allowlistPath: string;
  disabledDetectors: readonly string[];
  fileTimeoutMs?: number;
}

export function readInputs(env: NodeJS.ProcessEnv = process.env): ActionInputs {
  const fileTimeoutMs = parseOptionalPositiveInt(input(env, "file-timeout-ms"), "file-timeout-ms");

  return {
    githubToken: input(env, "github-token"),
    failOn: parseFailOn(input(env, "fail-on") || "block"),
    minSeverity: parseSeverity(input(env, "min-severity") || "info"),
    comment: parseBoolean(input(env, "comment") || "true"),
    maxFindings: parsePositiveInt(input(env, "max-findings") || "50", "max-findings"),
    allowlistPath: input(env, "allowlist-path") || ".obfuscan/allowlist.json",
    disabledDetectors: parseList(input(env, "disabled-detectors")),
    ...(fileTimeoutMs === undefined ? {} : { fileTimeoutMs }),
  };
}

function input(env: NodeJS.ProcessEnv, name: string): string {
  const githubKey = `INPUT_${name.replace(/ /g, "_").toUpperCase()}`;
  const legacyKey = `INPUT_${name.replace(/ /g, "_").replace(/-/g, "_").toUpperCase()}`;
  return (env[githubKey] ?? env[legacyKey] ?? "").trim();
}

function parseSeverity(value: string): Severity {
  if (value === "info" || value === "warn" || value === "block") return value;
  throw new Error(`min-severity must be one of info, warn, block; got ${value}`);
}

function parseFailOn(value: string): FailOn {
  if (value === "block" || value === "warn" || value === "never") return value;
  throw new Error(`fail-on must be one of block, warn, never; got ${value}`);
}

function parseBoolean(value: string): boolean {
  const normalized = value.toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  throw new Error(`boolean input must be true or false; got ${value}`);
}

function parsePositiveInt(value: string, name: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer; got ${value}`);
  }
  return parsed;
}

function parseOptionalPositiveInt(value: string, name: string): number | undefined {
  if (!value) return undefined;
  return parsePositiveInt(value, name);
}

function parseList(value: string): string[] {
  return value
    .split(/[\n,]/g)
    .map(item => item.trim())
    .filter(Boolean);
}
