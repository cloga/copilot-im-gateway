import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";
import {
  changedPaths,
  matchesAny,
  parseNameStatus,
} from "./path-policy.mjs";
import { coverageMetrics } from "./coverage-check.mjs";
import { validateWorkflows } from "./workflow-policy.mjs";

const requiredVerifyCommands = [
  "npm run lint",
  "npm run typecheck",
  "npm run test:coverage",
  "npm run coverage:check",
  "npm run build",
  "npm run audit:check",
  "npm run policy:check",
  "npm run release:verify",
];
const protectedDefaultBranch = "main";
const protectedRepositoryFullName = "cloga/copilot-im-gateway";
const protectedRepositoryId = "1343812506";
const protectedBranchAccount = "cloga";
const protectedBranchPrefix = "cloga/";
const protectedAutomationAccount = "dependabot[bot]";
const protectedAutomationPrefix = "dependabot/";
const pullRequestActions = new Set([
  "opened",
  "synchronize",
  "reopened",
  "ready_for_review",
  "edited",
]);

/**
 * @typedef {{
 *   workflowSha: string,
 *   eventName: string,
 *   eventAction: string,
 *   repositoryFullName: string,
 *   repositoryId: string,
 *   baseSha: string,
 *   baseRef: string,
 *   baseRepoFullName: string,
 *   baseRepoId: string,
 *   headSha: string,
 *   headRef: string,
 *   headRepoOwner: string,
 *   headRepoFullName: string,
 *   headRepoId: string,
 *   prAuthor: string,
 *   actor: string,
 * }} TrustContext
 */

/**
 * @param {{
 *   policy: Record<string, unknown>,
 *   changes: Array<{status: string, paths: string[]}>,
 *   trust: TrustContext,
 *   readBase: (path: string) => string | undefined,
 *   readTrusted: (path: string) => string | undefined,
 *   readHead: (path: string) => string | undefined,
 *   listTrustedFiles: (path: string) => string[],
 *   listHeadFiles: (path: string) => string[],
 * }} input
 */
export function evaluatePolicy(input) {
  const allowedPaths = requireStringArray(
    input.policy.allowedPaths,
    "allowedPaths",
  );
  const deniedPaths = requireStringArray(
    input.policy.deniedPaths,
    "deniedPaths",
  );
  const protectedPaths = requireStringArray(
    input.policy.protectedPaths,
    "protectedPaths",
  );
  const trustedExecutablePaths = requireStringArray(
    input.policy.trustedExecutablePaths,
    "trustedExecutablePaths",
  );
  const runtimeSecurityPaths = requireStringArray(
    input.policy.runtimeSecurityPaths,
    "runtimeSecurityPaths",
  );
  const regressionTestPaths = requireStringArray(
    input.policy.regressionTestPaths,
    "regressionTestPaths",
  );
  const paths = changedPaths(input.changes);

  validateTrustContext(input.policy, input.trust);
  for (const path of paths) {
    assert(
      matchesAny(path, allowedPaths),
      `changed path is not allowed by policy: ${path}`,
    );
    assert(
      path === ".env.example" || !matchesAny(path, deniedPaths),
      `changed path is denied by policy: ${path}`,
    );
  }

  const deletedTests = input.changes.flatMap((change) => {
    if (change.status.startsWith("D")) {
      return change.paths.filter((path) =>
        matchesAny(path, regressionTestPaths),
      );
    }
    if (
      change.status.startsWith("R") &&
      matchesAny(change.paths[0] ?? "", regressionTestPaths) &&
      !matchesAny(change.paths.at(-1) ?? "", regressionTestPaths)
    ) {
      return [change.paths[0] ?? ""];
    }
    return [];
  });
  assert(
    deletedTests.length === 0,
    `test deletion is denied: ${deletedTests.join(", ")}`,
  );

  if (paths.some((path) => matchesAny(path, runtimeSecurityPaths))) {
    assert(
      input.changes.some(
        (change) =>
          !change.status.startsWith("D") &&
          matchesAny(change.paths.at(-1) ?? "", regressionTestPaths),
      ),
      "security or runtime changes require a regression test change",
    );
  }

  const protectedChanges = paths.filter((path) =>
    matchesAny(path, protectedPaths),
  );

  validateCoverageBaseline(input.readBase, input.readHead);
  validateQualityGate(input.readHead);
  validateTrustedToolchain(input.readTrusted, input.readHead);
  validateTrustedExecutables(
    trustedExecutablePaths,
    input.readTrusted,
    input.readHead,
    input.listTrustedFiles,
    input.listHeadFiles,
  );
  validateWorkflows(input.listHeadFiles, input.readHead);
  validateContentPolicy(input.policy, input.listHeadFiles, input.readHead);
  validateArchitecture(input.policy, input.readHead);

  return {
    changedPaths: paths.length,
    protectedChanges,
  };
}

/**
 * @param {Record<string, unknown>} policy
 * @param {TrustContext} trust
 */
export function validateTrustContext(policy, trust) {
  const defaultBranch = requireString(policy.defaultBranch, "defaultBranch");
  const repositoryFullName = requireString(
    policy.repositoryFullName,
    "repositoryFullName",
  );
  const branchAccount = requireString(policy.branchAccount, "branchAccount");
  const branchAccountPrefix = requireString(
    policy.branchAccountPrefix,
    "branchAccountPrefix",
  );
  const automationBranchPrefixes = requireStringArray(
    policy.automationBranchPrefixes,
    "automationBranchPrefixes",
  );
  const automationAccount = requireString(
    policy.automationAccount,
    "automationAccount",
  );
  assert(
    defaultBranch === protectedDefaultBranch,
    `policy default branch must be ${protectedDefaultBranch}`,
  );
  assert(
    repositoryFullName === protectedRepositoryFullName,
    `policy repository must be ${protectedRepositoryFullName}`,
  );
  assert(
    branchAccount === protectedBranchAccount &&
      branchAccountPrefix === protectedBranchPrefix,
    "policy account branch identity is invalid",
  );
  assert(
    automationAccount === protectedAutomationAccount &&
      automationBranchPrefixes.length === 1 &&
      automationBranchPrefixes[0] === protectedAutomationPrefix,
    "policy automation branch identity is invalid",
  );
  assertFullSha(trust.workflowSha, "workflow SHA");
  assertFullSha(trust.baseSha, "base");
  assertFullSha(trust.headSha, "head");
  assert(
    trust.repositoryFullName === protectedRepositoryFullName,
    "event repository must be the protected repository",
  );
  assert(
    trust.repositoryId === protectedRepositoryId,
    "event repository ID must be the protected repository ID",
  );
  assert(
    trust.baseRepoFullName === protectedRepositoryFullName &&
      trust.baseRepoId === protectedRepositoryId,
    "event base must be the protected repository",
  );
  assert(
    trust.headRepoFullName === protectedRepositoryFullName &&
      trust.headRepoId === protectedRepositoryId &&
      trust.headRepoOwner === protectedBranchAccount,
    "event head must come from the protected repository",
  );

  if (trust.eventName === "pull_request") {
    assert(
      pullRequestActions.has(trust.eventAction),
      "pull request action is not protected",
    );
    validatePullRequestIdentity(
      trust,
      branchAccountPrefix,
      automationBranchPrefixes,
      branchAccount,
      automationAccount,
    );
    return;
  }
  assert(
    trust.eventName === "merge_group",
    "event must be pull_request or merge_group",
  );
  assert(
    trust.eventAction === "checks_requested",
    "merge group action must be checks_requested",
  );
  assert(
    trust.baseRef === `refs/heads/${protectedDefaultBranch}`,
    `merge group base ref must be refs/heads/${protectedDefaultBranch}`,
  );
}

/**
 * @param {TrustContext} trust
 * @param {string} branchAccountPrefix
 * @param {string[]} automationBranchPrefixes
 * @param {string} branchAccount
 * @param {string} automationAccount
 */
function validatePullRequestIdentity(
  trust,
  branchAccountPrefix,
  automationBranchPrefixes,
  branchAccount,
  automationAccount,
) {
  assert(
    trust.baseRef === protectedDefaultBranch,
    `pull request base branch must be ${protectedDefaultBranch}`,
  );
  if (
    automationBranchPrefixes.some(
      (prefix) => trust.headRef.startsWith(prefix) && trust.headRef !== prefix,
    )
  ) {
    assert(
      trust.prAuthor === automationAccount,
      "automation branches require the protected automation author",
    );
    assert(
      trust.actor === automationAccount,
      "automation branches require the protected automation actor",
    );
    return;
  }
  assert(
    trust.headRef.startsWith(branchAccountPrefix) &&
      trust.headRef !== branchAccountPrefix,
    `head branch must start with ${branchAccountPrefix}`,
  );
  assert(
    trust.prAuthor === branchAccount,
    "account branch author must match the protected account",
  );
  assert(
    trust.actor === branchAccount,
    "account branch actor must match the protected account",
  );
}

/**
 * @param {(path: string) => string | undefined} readBase
 * @param {(path: string) => string | undefined} readHead
 */
export function validateCoverageBaseline(readBase, readHead) {
  const baseText = readBase(".github/coverage-baseline.json");
  const headText = readHead(".github/coverage-baseline.json");
  assert(headText !== undefined, "coverage baseline is missing from head");
  if (baseText === undefined) {
    return;
  }
  const base = requireRecord(JSON.parse(baseText), "base coverage baseline");
  const head = requireRecord(JSON.parse(headText), "head coverage baseline");
  for (const metric of coverageMetrics) {
    const baseValue = base[metric];
    const headValue = head[metric];
    assert(
      typeof baseValue === "number" &&
        Number.isFinite(baseValue) &&
        typeof headValue === "number" &&
        Number.isFinite(headValue),
      `coverage baseline metric is invalid: ${metric}`,
    );
    assert(
      headValue >= baseValue,
      `coverage baseline decrease is denied: ${metric} ${headValue} < ${baseValue}`,
    );
  }
}

/** @param {(path: string) => string | undefined} readHead */
export function validateQualityGate(readHead) {
  const packageText = readHead("package.json");
  assert(packageText !== undefined, "package.json is missing from head");
  const manifest = requireRecord(JSON.parse(packageText), "package.json");
  const scripts = requireRecord(manifest.scripts, "package scripts");
  assert(scripts.check === "npm run verify", "npm run check must alias verify");
  const verify = requireString(scripts.verify, "verify script");
  assert(
    verify === requiredVerifyCommands.join(" && "),
    "verify script must preserve the protected canonical closure",
  );
  const protectedScripts = {
    "audit:check": "npm audit --audit-level=high",
    build: "tsc -p tsconfig.build.json",
    "coverage:check": "node scripts/coverage-check.mjs",
    lint: "eslint .",
    "policy:check": "node scripts/policy-check.mjs",
    "release:installer":
      "powershell -NoProfile -ExecutionPolicy Bypass -File scripts/installer/build-windows-installer.ps1",
    "release:installer:smoke":
      "powershell -NoProfile -ExecutionPolicy Bypass -File scripts/installer/smoke-windows-installer.ps1",
    "release:package": "node scripts/package-release.mjs",
    "release:validate": "node scripts/validate-release.mjs",
    "release:verify": "node scripts/verify-release.mjs",
    "test:coverage": "vitest run --coverage",
    typecheck: "tsc --noEmit",
    verify: requiredVerifyCommands.join(" && "),
  };
  for (const [name, expected] of Object.entries(protectedScripts)) {
    assert(
      scripts[name] === expected,
      `protected package script changed: ${name}`,
    );
    for (const lifecycle of [`pre${name}`, `post${name}`]) {
      assert(
        !(lifecycle in scripts),
        `protected package lifecycle hook is denied: ${lifecycle}`,
      );
    }
  }
}

/**
 * @param {string[]} patterns
 * @param {(path: string) => string | undefined} readTrusted
 * @param {(path: string) => string | undefined} readHead
 * @param {(path: string) => string[]} listTrustedFiles
 * @param {(path: string) => string[]} listHeadFiles
 */
export function validateTrustedExecutables(
  patterns,
  readTrusted,
  readHead,
  listTrustedFiles,
  listHeadFiles,
) {
  assert(patterns.length > 0, "trustedExecutablePaths must not be empty");
  const paths = new Set([
    ...listTrustedFiles(""),
    ...listHeadFiles(""),
  ]);
  for (const path of [...paths].sort()) {
    if (!matchesAny(path, patterns)) {
      continue;
    }
    const trusted = readTrusted(path);
    const head = readHead(path);
    assert(
      trusted !== undefined && head !== undefined && head === trusted,
      `trusted executable differs from workflow SHA: ${path}`,
    );
  }
  for (const pattern of patterns) {
    assert(
      [...paths].some((path) => matchesAny(path, [pattern])),
      `trusted executable pattern matches no files: ${pattern}`,
    );
  }
}

/**
 * @param {(path: string) => string | undefined} readTrusted
 * @param {(path: string) => string | undefined} readHead
 */
export function validateTrustedToolchain(readTrusted, readHead) {
  const trustedPackage = parseJsonRecord(
    readTrusted("package.json"),
    "trusted package.json",
  );
  const headPackage = parseJsonRecord(readHead("package.json"), "package.json");
  for (const field of [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ]) {
    assert(
      isDeepStrictEqual(trustedPackage[field], headPackage[field]),
      `dependency declarations differ from workflow SHA: ${field}`,
    );
  }

  const trustedLock = normalizePackageLock(
    parseJsonRecord(
      readTrusted("package-lock.json"),
      "trusted package-lock.json",
    ),
  );
  const headLock = normalizePackageLock(
    parseJsonRecord(readHead("package-lock.json"), "package-lock.json"),
  );
  assert(
    isDeepStrictEqual(trustedLock, headLock),
    "package-lock.json differs from workflow SHA",
  );
}

/** @param {Record<string, unknown>} lock */
function normalizePackageLock(lock) {
  const normalized = structuredClone(lock);
  delete normalized.version;
  const packages = requireRecord(
    normalized.packages,
    "package-lock.json packages",
  );
  const root = requireRecord(packages[""], "package-lock.json root package");
  delete root.version;
  return normalized;
}

/**
 * @param {string | undefined} source
 * @param {string} label
 */
function parseJsonRecord(source, label) {
  assert(source !== undefined, `${label} is missing`);
  return requireRecord(JSON.parse(source), label);
}

/**
 * @param {(path: string) => string[]} listHeadFiles
 * @param {(path: string) => string | undefined} readHead
 */
/**
 * @param {Record<string, unknown>} policy
 * @param {(path: string) => string[]} listHeadFiles
 * @param {(path: string) => string | undefined} readHead
 */
export function validateContentPolicy(policy, listHeadFiles, readHead) {
  const productPatterns = requireStringArray(
    policy.forbiddenProductPatterns,
    "forbiddenProductPatterns",
  );
  const productPaths = requireStringArray(
    policy.productCodePaths,
    "productCodePaths",
  );
  for (const path of listHeadFiles("")) {
    const patterns = matchesAny(path, productPaths)
      ? productPatterns
      : matchesAny(path, ["tests/**/*.test.ts"])
        ? requireStringArray(
            policy.forbiddenTestPatterns,
            "forbiddenTestPatterns",
          )
        : [];
    if (patterns.length === 0) {
      continue;
    }
    const contents = readHead(path);
    assert(contents !== undefined, `policy-scanned file is missing: ${path}`);
    for (const pattern of patterns) {
      assert(
        !contents.includes(pattern),
        `forbidden content in ${path}: ${pattern}`,
      );
    }
  }
}

/**
 * @param {Record<string, unknown>} policy
 * @param {(path: string) => string | undefined} readHead
 */
export function validateArchitecture(policy, readHead) {
  const architectureAssertions = policy.architectureAssertions;
  assert(
    Array.isArray(architectureAssertions),
    "architectureAssertions is invalid",
  );
  for (const value of architectureAssertions) {
    const assertion = requireRecord(value, "architecture assertion");
    const path = requireString(assertion.path, "architecture assertion path");
    const contents = readHead(path);
    assert(contents !== undefined, `architecture file is missing: ${path}`);
    for (const expected of requireStringArray(
      assertion.mustContain,
      `${path} mustContain`,
    )) {
      assert(
        contents.includes(expected),
        `architecture invariant is missing from ${path}: ${expected}`,
      );
    }
    for (const denied of requireStringArray(
      assertion.mustNotContain,
      `${path} mustNotContain`,
    )) {
      assert(
        !contents.includes(denied),
        `architecture invariant is violated in ${path}: ${denied}`,
      );
    }
  }
}

/**
 * @param {{
 *   trust: TrustContext,
 * }} input
 */
export function evaluateGovernance(input) {
  const { trust } = input;
  assertFullCommit(trust.workflowSha, "workflow SHA");
  assertFullCommit(trust.baseSha, "base");
  assertFullCommit(trust.headSha, "head");
  assert(
    git(["rev-parse", "HEAD"]).stdout.trim() === trust.workflowSha,
    "checked out source does not match the workflow SHA",
  );
  assert(
    git(["rev-parse", "FETCH_HEAD"], false).stdout.trim() === trust.headSha,
    "fetched untrusted head does not match the event head SHA",
  );
  const policy = requireRecord(
    JSON.parse(readAt(trust.workflowSha, ".github/agent-policy.json")),
    "trusted workflow policy",
  );
  validateTrustContext(policy, trust);
  return evaluatePolicy({
    policy,
    changes: parseNameStatus(
      git([
        "diff",
        "--name-status",
        "--find-renames",
        trust.baseSha,
        trust.headSha,
        "--",
      ]).stdout,
    ),
    trust,
    readBase: (path) => readAtOptional(trust.baseSha, path),
    readTrusted: (path) => readAtOptional(trust.workflowSha, path),
    readHead: (path) => readAtOptional(trust.headSha, path),
    listTrustedFiles: (directory) => listAt(trust.workflowSha, directory),
    listHeadFiles: (directory) => listAt(trust.headSha, directory),
  });
}

/** @param {string} ref @param {string} path */
function readAt(ref, path) {
  const value = readAtOptional(ref, path);
  assert(value !== undefined, `required file is missing: ${path}`);
  return value;
}

/** @param {string} ref @param {string} path */
function readAtOptional(ref, path) {
  const result = git(["show", `${ref}:${path}`], false);
  return result.status === 0 ? result.stdout : undefined;
}

/** @param {string} ref @param {string} directory */
function listAt(ref, directory) {
  const args = ["ls-tree", "-r", "--name-only", ref];
  if (directory) {
    args.push("--", directory);
  }
  return git(args).stdout.split(/\r?\n/u).filter(Boolean);
}

/** @param {string} ref @param {string} label */
function assertFullCommit(ref, label) {
  assertFullSha(ref, label);
  assert(
    git(["cat-file", "-e", `${ref}^{commit}`], false).status === 0,
    `${label} commit is missing`,
  );
}

/** @param {string} value @param {string} label */
function assertFullSha(value, label) {
  assert(/^[a-f0-9]{40}$/u.test(value), `${label} must be a full commit SHA`);
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

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {string}
 */
function requireString(value, label) {
  assert(typeof value === "string", `${label} is invalid`);
  return value;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {string[]}
 */
function requireStringArray(value, label) {
  assert(
    Array.isArray(value) && value.every((entry) => typeof entry === "string"),
    `${label} is invalid`,
  );
  return value;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {Record<string, unknown>}
 */
function requireRecord(value, label) {
  assert(
    value !== null && typeof value === "object" && !Array.isArray(value),
    `${label} is invalid`,
  );
  return /** @type {Record<string, unknown>} */ (value);
}

/**
 * @param {unknown} condition
 * @param {string} message
 * @returns {asserts condition}
 */
function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

/** @param {string[]} argv */
function parseArgs(argv) {
  const values = new Map();
  const allowed = new Set([
    "workflow-sha",
    "event-name",
    "event-action",
    "repository",
    "repository-id",
    "base",
    "base-ref",
    "base-repo-full-name",
    "base-repo-id",
    "head",
    "head-ref",
    "head-repo-owner",
    "head-repo-full-name",
    "head-repo-id",
    "pr-author",
    "actor",
  ]);
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    assert(
      typeof key === "string" && key.startsWith("--") && value,
      "invalid governance arguments",
    );
    const name = key.slice(2);
    assert(
      allowed.has(name) && !values.has(name),
      "invalid governance arguments",
    );
    values.set(name, value);
  }
  return {
    trust: {
      workflowSha: values.get("workflow-sha") ?? "",
      eventName: values.get("event-name") ?? "",
      eventAction: values.get("event-action") ?? "",
      repositoryFullName: values.get("repository") ?? "",
      repositoryId: values.get("repository-id") ?? "",
      baseSha: values.get("base") ?? "",
      baseRef: values.get("base-ref") ?? "",
      baseRepoFullName: values.get("base-repo-full-name") ?? "",
      baseRepoId: values.get("base-repo-id") ?? "",
      headSha: values.get("head") ?? "",
      headRef: values.get("head-ref") ?? "",
      headRepoOwner: values.get("head-repo-owner") ?? "",
      headRepoFullName: values.get("head-repo-full-name") ?? "",
      headRepoId: values.get("head-repo-id") ?? "",
      prAuthor: values.get("pr-author") ?? "",
      actor: values.get("actor") ?? "",
    },
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const result = evaluateGovernance(parseArgs(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
