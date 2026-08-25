import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { parseNameStatus } from "./path-policy.mjs";
import { evaluatePolicy } from "./governance-check.mjs";

const root = process.cwd();
const policy = JSON.parse(
  readFileSync(path.join(root, ".github", "agent-policy.json"), "utf8"),
);
const base = findBase(policy.defaultBranch);
const eventHeadRef =
  process.env.AGENT_POLICY_HEAD_REF ?? process.env.GITHUB_HEAD_REF;
const trustedHeadRef =
  eventHeadRef &&
  process.env.GITHUB_REF_TYPE !== "tag" &&
  eventHeadRef !== policy.defaultBranch
    ? eventHeadRef
    : `${policy.branchAccount}/local-policy`;
const headCommit = git(["rev-parse", "HEAD"]).stdout.trim();
const trustedAuthor = trustedHeadRef.startsWith("dependabot/")
  ? policy.automationAccount
  : policy.branchAccount;

const changes = parseNameStatus(
  git(["diff", "--name-status", "--find-renames", base, "--"]).stdout,
);
for (const file of git(["ls-files", "--others", "--exclude-standard"]).stdout
  .split(/\r?\n/u)
  .filter(Boolean)) {
  changes.push({ status: "A", paths: [file.replaceAll("\\", "/")] });
}

const result = evaluatePolicy({
  policy,
  changes,
  trust: {
    workflowSha: headCommit,
    eventName: "pull_request",
    eventAction: "synchronize",
    repositoryFullName: policy.repositoryFullName,
    repositoryId: "1343812506",
    baseSha: base,
    baseRef: policy.defaultBranch,
    baseRepoFullName: policy.repositoryFullName,
    baseRepoId: "1343812506",
    headSha: headCommit,
    headRef: trustedHeadRef,
    headRepoOwner: policy.branchAccount,
    headRepoFullName: policy.repositoryFullName,
    headRepoId: "1343812506",
    prAuthor: trustedAuthor,
    actor: trustedAuthor,
  },
  readBase: (file) => readAtOptional(base, file),
  readTrusted: (file) => readWorkingFile(file),
  readHead: (file) => readWorkingFile(file),
  listTrustedFiles: (directory) => listWorkingFiles(directory),
  listHeadFiles: (directory) => listWorkingFiles(directory),
});

process.stdout.write(
  `Local policy passed for ${result.changedPaths} changed paths against ${base}.\n`,
);

/** @param {string} defaultBranch */
function findBase(defaultBranch) {
  if (process.env.AGENT_POLICY_BASE) {
    return process.env.AGENT_POLICY_BASE;
  }
  for (const candidate of [`origin/${defaultBranch}`, defaultBranch]) {
    if (git(["rev-parse", "--verify", candidate], false).status === 0) {
      return git(["merge-base", "HEAD", candidate]).stdout.trim();
    }
  }
  return git(["rev-parse", "HEAD^"]).stdout.trim();
}

/** @param {string} ref @param {string} file */
function readAtOptional(ref, file) {
  const result = git(["show", `${ref}:${file}`], false);
  return result.status === 0 ? result.stdout : undefined;
}

/** @param {string} file */
function readWorkingFile(file) {
  const absolutePath = path.join(root, ...file.split("/"));
  try {
    return statSync(absolutePath).isFile()
      ? readFileSync(absolutePath, "utf8")
      : undefined;
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "ENOENT"
    ) {
      return undefined;
    }
    throw error;
  }
}

/**
 * @param {string} directory
 * @returns {string[]}
 */
function listWorkingFiles(directory) {
  const start = path.join(root, ...directory.split("/").filter(Boolean));
  try {
    return walk(start).map((file) =>
      path.relative(root, file).replaceAll("\\", "/"),
    );
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "ENOENT"
    ) {
      return [];
    }
    throw error;
  }
}

/**
 * @param {string} directory
 * @returns {string[]}
 */
function walk(directory) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".git") {
      continue;
    }
    const absolutePath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...walk(absolutePath));
    } else if (entry.isFile()) {
      files.push(absolutePath);
    }
  }
  return files;
}

/** @param {string[]} args @param {boolean} [required] */
function git(args, required = true) {
  const result = spawnSync("git", args, {
    encoding: "utf8",
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (required && result.status !== 0) {
    throw new Error(result.stderr || `git ${args.join(" ")} failed`);
  }
  return result;
}
