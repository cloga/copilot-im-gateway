import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
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

/**
 * @param {{
 *   policy: Record<string, unknown>,
 *   changes: Array<{status: string, paths: string[]}>,
 *   headRef: string,
 *   identity: {baseRef:string, baseRepoFullName:string, headRepoOwner:string, headRepoFullName:string, prAuthor:string, eventAction:string, eventActor:string, headProvenanceVerified:boolean},
 *   manualGovernanceApproved: boolean,
 *   readBase: (path: string) => string | undefined,
 *   readHead: (path: string) => string | undefined,
 *   listHeadFiles: (path: string) => string[],
 *   enforceManualApproval?: boolean,
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
  const runtimeSecurityPaths = requireStringArray(
    input.policy.runtimeSecurityPaths,
    "runtimeSecurityPaths",
  );
  const regressionTestPaths = requireStringArray(
    input.policy.regressionTestPaths,
    "regressionTestPaths",
  );
  const paths = changedPaths(input.changes);

  validatePullRequestIdentity(input.policy, input.headRef, input.identity);
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
  if (
    input.enforceManualApproval !== false &&
    protectedChanges.length > 0 &&
    !input.manualGovernanceApproved
  ) {
    throw new Error(
      `protected changes require a fresh manual-governance approval: ${protectedChanges.join(", ")}`,
    );
  }

  validateCoverageBaseline(input.readBase, input.readHead);
  validateQualityGate(input.readHead);
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
 * @param {string} headRef
 * @param {{baseRef:string, baseRepoFullName:string, headRepoOwner:string, headRepoFullName:string, prAuthor:string, eventAction:string, eventActor:string, headProvenanceVerified:boolean}} identity
 */
export function validatePullRequestIdentity(policy, headRef, identity) {
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
    identity.baseRef === protectedDefaultBranch,
    `pull request base branch must be ${protectedDefaultBranch}`,
  );
  assert(
    identity.baseRepoFullName === protectedRepositoryFullName,
    "pull request base must be the protected repository",
  );
  assert(
    identity.headRepoFullName === repositoryFullName &&
      identity.headRepoOwner === branchAccount,
    "pull request head must come from the protected repository",
  );
  if (automationBranchPrefixes.some((prefix) => headRef.startsWith(prefix))) {
    assert(
      identity.prAuthor === automationAccount,
      "automation branches require the protected automation author",
    );
    validateAuthoringActor(identity, automationAccount);
    return;
  }
  assert(
    headRef === defaultBranch || headRef.startsWith(branchAccountPrefix),
    `head branch must be ${defaultBranch} or start with ${branchAccountPrefix}`,
  );
  assert(
    identity.prAuthor === branchAccount,
    "account branch author must match the protected account",
  );
  validateAuthoringActor(identity, branchAccount);
}

/**
 * Label and reopen events may be performed by maintainers. Events that create
 * or update the head must run as the protected branch author.
 *
 * @param {{eventAction:string,eventActor:string,headProvenanceVerified:boolean}} identity
 * @param {string} expectedActor
 */
function validateAuthoringActor(identity, expectedActor) {
  if (
    identity.eventAction === "opened" ||
    identity.eventAction === "synchronize"
  ) {
    assert(
      identity.eventActor === expectedActor,
      "head-authoring event actor must match the protected account",
    );
  } else {
    assert(
      identity.headProvenanceVerified,
      "current head SHA lacks trusted authoring-event provenance",
    );
  }
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
    "coverage:check": "node scripts/coverage-check.mjs",
    "policy:check": "node scripts/policy-check.mjs",
    "release:verify": "node scripts/verify-release.mjs",
    "test:coverage": "vitest run --coverage",
  };
  for (const [name, expected] of Object.entries(protectedScripts)) {
    assert(
      scripts[name] === expected,
      `protected package script changed: ${name}`,
    );
  }
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
 *   base: string,
 *   baseRef: string,
 *   baseRepoFullName: string,
 *   head: string,
 *   headRef: string,
 *   identity: {baseRef:string, baseRepoFullName:string, headRepoOwner:string, headRepoFullName:string, prAuthor:string, eventAction:string, eventActor:string, headProvenanceVerified:boolean},
 *   manualGovernanceApproved: boolean,
 * }} input
 */
export function evaluateGovernance(input) {
  assertFullCommit(input.base, "base");
  assertFullCommit(input.head, "head");
  assert(
    git(["rev-parse", "FETCH_HEAD"], false).stdout.trim() === input.head,
    "fetched pull request head does not match the event head SHA",
  );
  const policy = requireRecord(
    JSON.parse(readAt(input.base, ".github/agent-policy.json")),
    "base policy",
  );
  return evaluatePolicy({
    policy,
    changes: parseNameStatus(
      git(["diff", "--name-status", "--find-renames", input.base, input.head])
        .stdout,
    ),
    headRef: input.headRef,
    identity: {
      ...input.identity,
      baseRef: input.baseRef,
      baseRepoFullName: input.baseRepoFullName,
    },
    manualGovernanceApproved: input.manualGovernanceApproved,
    readBase: (path) => readAtOptional(input.base, path),
    readHead: (path) => readAtOptional(input.head, path),
    listHeadFiles: (directory) => listAt(input.head, directory),
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
  assert(/^[a-f0-9]{40}$/u.test(ref), `${label} must be a full commit SHA`);
  assert(
    git(["cat-file", "-e", `${ref}^{commit}`], false).status === 0,
    `${label} commit is missing`,
  );
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
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    assert(
      typeof key === "string" && key.startsWith("--") && value,
      "invalid governance arguments",
    );
    values.set(key.slice(2), value);
  }
  return {
    base: values.get("base") ?? "",
    baseRef: values.get("base-ref") ?? "",
    baseRepoFullName: values.get("base-repo-full-name") ?? "",
    head: values.get("head") ?? "",
    headRef: values.get("head-ref") ?? "",
    identity: {
      baseRef: values.get("base-ref") ?? "",
      baseRepoFullName: values.get("base-repo-full-name") ?? "",
      headRepoOwner: values.get("head-repo-owner") ?? "",
      headRepoFullName: values.get("head-repo-full-name") ?? "",
      prAuthor: values.get("pr-author") ?? "",
      eventAction: values.get("event-action") ?? "",
      eventActor: values.get("event-actor") ?? "",
      headProvenanceVerified:
        values.get("head-provenance-verified") === "true",
    },
    manualGovernanceApproved:
      values.get("manual-governance-approved") === "true",
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const result = evaluateGovernance(parseArgs(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
