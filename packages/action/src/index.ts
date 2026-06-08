import { execFile } from "node:child_process";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { scan, type Allowlist, type Finding, type ScanResult } from "@obfuscan/core";
import { readInputs } from "./inputs.js";
import { BUNDLED_ENGINE_VERSION } from "./generated.js";
import { countFindings, formatMarkdown, reportMarker, shouldFail } from "./report.js";

const execFileAsync = promisify(execFile);

interface GitHubContext {
  owner: string;
  repo: string;
  eventName: string;
  apiUrl: string;
  event: Record<string, unknown>;
  pullNumber?: number;
  sha?: string;
  before?: string;
  after?: string;
}

interface Comment {
  id: number;
  body?: string;
}

async function main(): Promise<void> {
  const inputs = readInputs();
  const workspace = process.env["GITHUB_WORKSPACE"] || process.cwd();
  configureBundledRulesDir();

  const context = await readGitHubContext();
  const diff = await readDiff(context, inputs.githubToken);
  const allowlist = await loadAllowlist(path.resolve(workspace, inputs.allowlistPath));

  const result = await scan(
    { diff },
    {
      fileResolver: fileResolver(workspace),
      allowlist,
      minSeverity: inputs.minSeverity,
      disabledDetectors: inputs.disabledDetectors,
      logger: actionLogger(),
      ...(inputs.fileTimeoutMs === undefined ? {} : { fileTimeoutMs: inputs.fileTimeoutMs }),
    },
  );

  const report = formatMarkdown(result, {
    maxFindings: inputs.maxFindings,
    owner: context.owner,
    repo: context.repo,
    engineVersion: normalizeEngineVersion(result),
    ...(context.sha ? { sha: context.sha } : {}),
  });

  writeAnnotations(result.findings);
  await writeStepSummary(report);

  if (inputs.comment && context.pullNumber !== undefined) {
    await upsertPullRequestComment(context, inputs.githubToken, report);
  } else if (inputs.comment) {
    warning("comment=true is ignored outside pull_request events");
  }

  const counts = countFindings(result.findings);
  const fail = shouldFail(result.findings, inputs.failOn);
  await Promise.all([
    setOutput("findings-total", String(result.findings.length)),
    setOutput("findings-block", String(counts.block)),
    setOutput("findings-warn", String(counts.warn)),
    setOutput("findings-info", String(counts.info)),
    setOutput("conclusion", fail ? "fail" : "pass"),
  ]);

  if (fail) {
    throw new Error(`obfuscan found findings at or above fail-on=${inputs.failOn}`);
  }
}

function configureBundledRulesDir(): void {
  if (process.env["OBFUSCAN_RULES_DIR"]) return;
  const here = path.dirname(fileURLToPath(import.meta.url));
  process.env["OBFUSCAN_RULES_DIR"] = path.join(here, "rules", "languages");
}

async function readGitHubContext(): Promise<GitHubContext> {
  const repository = process.env["GITHUB_REPOSITORY"];
  if (!repository || !repository.includes("/")) {
    throw new Error("GITHUB_REPOSITORY is required");
  }
  const [owner, repo] = repository.split("/", 2) as [string, string];
  const eventPath = process.env["GITHUB_EVENT_PATH"];
  const event = eventPath ? JSON.parse(await fs.readFile(eventPath, "utf8")) as Record<string, unknown> : {};
  const eventName = process.env["GITHUB_EVENT_NAME"] || "";
  const pullRequest = event["pull_request"] as Record<string, unknown> | undefined;
  const baseApiUrl = process.env["GITHUB_API_URL"] || "https://api.github.com";
  const before = typeof event["before"] === "string" ? event["before"] : undefined;
  const after = typeof event["after"] === "string" ? event["after"] : undefined;

  const sha = readHeadSha(event) || process.env["GITHUB_SHA"];

  return {
    owner,
    repo,
    eventName,
    apiUrl: baseApiUrl.replace(/\/$/, ""),
    event,
    ...(typeof pullRequest?.["number"] === "number" ? { pullNumber: pullRequest["number"] as number } : {}),
    ...(sha ? { sha } : {}),
    ...(before ? { before } : {}),
    ...(after ? { after } : {}),
  };
}

function readHeadSha(event: Record<string, unknown>): string | undefined {
  const pullRequest = event["pull_request"] as Record<string, unknown> | undefined;
  const head = pullRequest?.["head"] as Record<string, unknown> | undefined;
  return typeof head?.["sha"] === "string" ? head["sha"] : undefined;
}

async function readDiff(context: GitHubContext, token: string): Promise<string> {
  if (context.pullNumber !== undefined) {
    return githubRequestText(
      context,
      token,
      `/repos/${context.owner}/${context.repo}/pulls/${context.pullNumber}`,
      "application/vnd.github.v3.diff",
    );
  }

  if (context.eventName === "push" && context.before && context.after) {
    return githubRequestText(
      context,
      token,
      `/repos/${context.owner}/${context.repo}/compare/${context.before}...${context.after}`,
      "application/vnd.github.diff",
    );
  }

  return readLocalDiff();
}

async function readLocalDiff(): Promise<string> {
  try {
    const { stdout } = await execFileAsync("git", ["diff", "--no-ext-diff", "--unified=0", "HEAD~1...HEAD"], {
      maxBuffer: 50 * 1024 * 1024,
    });
    return stdout;
  } catch (err) {
    throw new Error(`unable to determine a diff for this event: ${String(err)}`);
  }
}

async function loadAllowlist(filePath: string): Promise<Allowlist> {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw) as Allowlist;
  } catch {
    return {};
  }
}

function fileResolver(workspace: string) {
  const root = path.resolve(workspace);
  return async (relativePath: string): Promise<string | null> => {
    const full = path.resolve(root, relativePath);
    if (full !== root && !full.startsWith(root + path.sep)) return null;
    try {
      const stat = await fs.stat(full);
      if (!stat.isFile()) return null;
      return await fs.readFile(full, "utf8");
    } catch {
      return null;
    }
  };
}

async function upsertPullRequestComment(context: GitHubContext, token: string, body: string): Promise<void> {
  if (!token) {
    warning("github-token is empty; skipping pull request comment");
    return;
  }
  if (context.pullNumber === undefined) return;

  try {
    const comments = await githubRequestJson<Comment[]>(
      context,
      token,
      `/repos/${context.owner}/${context.repo}/issues/${context.pullNumber}/comments?per_page=100`,
      "GET",
    );
    const existing = comments.find(comment => comment.body?.includes(reportMarker()));
    if (existing) {
      await githubRequestJson(
        context,
        token,
        `/repos/${context.owner}/${context.repo}/issues/comments/${existing.id}`,
        "PATCH",
        { body },
      );
    } else {
      await githubRequestJson(
        context,
        token,
        `/repos/${context.owner}/${context.repo}/issues/${context.pullNumber}/comments`,
        "POST",
        { body },
      );
    }
  } catch (err) {
    warning(`failed to write pull request comment: ${String(err)}`);
  }
}

async function githubRequestText(context: GitHubContext, token: string, route: string, accept: string): Promise<string> {
  const response = await fetch(context.apiUrl + route, {
    headers: githubHeaders(token, accept),
  });
  if (!response.ok) {
    throw new Error(`GitHub API ${route} failed with ${response.status}: ${await response.text()}`);
  }
  return response.text();
}

async function githubRequestJson<T>(
  context: GitHubContext,
  token: string,
  route: string,
  method: "GET" | "POST" | "PATCH",
  body?: unknown,
): Promise<T> {
  const response = await fetch(context.apiUrl + route, {
    method,
    headers: {
      ...githubHeaders(token, "application/vnd.github+json"),
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!response.ok) {
    throw new Error(`GitHub API ${method} ${route} failed with ${response.status}: ${await response.text()}`);
  }
  return response.json() as Promise<T>;
}

function githubHeaders(token: string, accept: string): Record<string, string> {
  return {
    accept,
    "user-agent": "obfuscan-github-action",
    "x-github-api-version": "2022-11-28",
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  };
}

function writeAnnotations(findings: readonly Finding[]): void {
  for (const finding of findings) {
    const command = finding.severity === "block" ? "error" : finding.severity === "warn" ? "warning" : "notice";
    const title = finding.ruleId;
    const message = `${finding.reason}\n${finding.snippet}`;
    console.log(`::${command} file=${escapeProperty(finding.file)},line=${finding.line},title=${escapeProperty(title)}::${escapeData(message)}`);
  }
}

async function writeStepSummary(report: string): Promise<void> {
  const summaryPath = process.env["GITHUB_STEP_SUMMARY"];
  if (!summaryPath) return;
  await fs.appendFile(summaryPath, report + "\n", "utf8");
}

async function setOutput(name: string, value: string): Promise<void> {
  const outputPath = process.env["GITHUB_OUTPUT"];
  if (!outputPath) {
    console.log(`${name}=${value}`);
    return;
  }
  try {
    await fs.appendFile(outputPath, `${name}=${value}\n`, "utf8");
  } catch (err) {
    warning(`failed to set output ${name}: ${String(err)}`);
  }
}

function actionLogger() {
  return {
    debug: (msg: string) => console.log(`::debug::${escapeData(msg)}`),
    info: (msg: string) => console.log(msg),
    warn: (msg: string) => warning(msg),
    error: (msg: string) => console.log(`::error::${escapeData(msg)}`),
  };
}

function normalizeEngineVersion(result: ScanResult): string {
  return result.engineVersion === "0.0.0-source" ? BUNDLED_ENGINE_VERSION : result.engineVersion;
}

function warning(message: string): void {
  console.log(`::warning::${escapeData(message)}`);
}

function escapeData(value: string): string {
  return value.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

function escapeProperty(value: string): string {
  return escapeData(value).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

main().catch(err => {
  console.log(`::error::${escapeData(err instanceof Error ? err.message : String(err))}`);
  process.exitCode = 1;
});
