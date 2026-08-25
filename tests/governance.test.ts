import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { assertCoverageFloor } from "../scripts/coverage-check.mjs";
import {
  evaluatePolicy,
  validateCoverageBaseline,
  validateTrustedExecutables,
  validateTrustedToolchain,
  validateTrustContext,
} from "../scripts/governance-check.mjs";
import {
  changedPaths,
  matchesGlob,
  parseNameStatus,
} from "../scripts/path-policy.mjs";
import {
  parseTrustedWorkflow,
  validateActionReferences,
  validateWorkflows,
} from "../scripts/workflow-policy.mjs";

const repositoryFullName = "cloga/copilot-im-gateway";
const repositoryId = "1343812506";
const workflowSha = "1".repeat(40);
const baseSha = "2".repeat(40);
const headSha = "3".repeat(40);
const governancePath = ".github/workflows/governance-required.yml";
const workflowPaths = [
  ".github/workflows/ci.yml",
  governancePath,
  ".github/workflows/release.yml",
];
const qualityPackage = JSON.stringify({
  scripts: {
    "audit:check": "npm audit --audit-level=high",
    build: "tsc -p tsconfig.build.json",
    check: "npm run verify",
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
    verify:
      "npm run lint && npm run typecheck && npm run test:coverage && npm run coverage:check && npm run build && npm run audit:check && npm run policy:check && npm run release:verify",
  },
});
const coverageBaseline = JSON.stringify({
  lines: 1,
  branches: 1,
  functions: 1,
  statements: 1,
});
const policy = {
  defaultBranch: "main",
  repositoryFullName,
  branchAccount: "cloga",
  branchAccountPrefix: "cloga/",
  automationAccount: "dependabot[bot]",
  automationBranchPrefixes: ["dependabot/"],
  allowedPaths: [
    "src/**",
    "tests/**",
    ".github/**",
    "package.json",
    "docs/**",
    "scripts/**",
  ],
  deniedPaths: ["**/.env"],
  protectedPaths: [".github/**"],
  trustedExecutablePaths: [
    "eslint.config.mjs",
    "scripts/coverage-check.mjs",
    "scripts/installer/**",
    "tsconfig.build.json",
    "tsconfig.json",
    "vitest.config.ts",
  ],
  runtimeSecurityPaths: ["src/**"],
  regressionTestPaths: ["tests/**/*.test.ts"],
  productCodePaths: ["src/**"],
  forbiddenProductPatterns: ["--acp"],
  forbiddenTestPatterns: [["ilinkai", "weixin.qq.com"].join(".")],
  architectureAssertions: [],
};
const pullRequestTrust = {
  workflowSha,
  eventName: "pull_request",
  eventAction: "synchronize",
  repositoryFullName,
  repositoryId,
  baseSha,
  baseRef: "main",
  baseRepoFullName: repositoryFullName,
  baseRepoId: repositoryId,
  headSha,
  headRef: "cloga/required-governance",
  headRepoOwner: "cloga",
  headRepoFullName: repositoryFullName,
  headRepoId: repositoryId,
  prAuthor: "cloga",
  actor: "cloga",
};
const mergeGroupTrust = {
  ...pullRequestTrust,
  eventName: "merge_group",
  eventAction: "checks_requested",
  baseRef: "refs/heads/main",
  headRef: "refs/heads/gh-readonly-queue/main/pr-1-deadbeef",
  prAuthor: "",
  actor: "github-actions[bot]",
};

describe("governance policy", () => {
  it("matches recursive globs and evaluates both sides of renames", () => {
    expect(matchesGlob("src/core/security.ts", "src/**")).toBe(true);
    expect(matchesGlob("src/security.ts", "src/**/*.ts")).toBe(true);
    expect(matchesGlob(".env", "**/.env")).toBe(true);
    expect(matchesGlob("docs/security.md", "src/**")).toBe(false);

    const changes = parseNameStatus(
      "R100\tsrc/old.ts\tdocs/new.ts\nM\ttests/security.test.ts\n",
    );
    expect(changedPaths(changes)).toEqual([
      "src/old.ts",
      "docs/new.ts",
      "tests/security.test.ts",
    ]);
  });

  it("treats coverage baselines as floors and denies decreases", () => {
    const summary = {
      total: {
        lines: { pct: 80 },
        branches: { pct: 70 },
        functions: { pct: 90 },
        statements: { pct: 80 },
      },
    };
    expect(
      assertCoverageFloor(
        { lines: 79, branches: 70, functions: 85, statements: 79 },
        summary,
      ),
    ).toEqual({
      lines: 80,
      branches: 70,
      functions: 90,
      statements: 80,
    });
    expect(() =>
      validateCoverageBaseline(
        () =>
          JSON.stringify({
            lines: 80,
            branches: 70,
            functions: 90,
            statements: 80,
          }),
        () =>
          JSON.stringify({
            lines: 79.99,
            branches: 70,
            functions: 90,
            statements: 80,
          }),
      ),
    ).toThrow("decrease is denied");
  });

  it("reports protected paths without approval and preserves semantic gates", () => {
    const files = policyFiles();
    const read = (file: string) => files.get(file);
    const list = (directory: string) =>
      [...files.keys()].filter(
        (file) => !directory || file.startsWith(`${directory}/`),
      );
    const baseInput = {
      policy,
      trust: pullRequestTrust,
      readBase: read,
      readTrusted: read,
      readHead: read,
      listTrustedFiles: list,
      listHeadFiles: list,
    };

    expect(() =>
      evaluatePolicy({
        ...baseInput,
        changes: parseNameStatus("M\tsrc/core/security.ts\n"),
      }),
    ).toThrow("require a regression test");

    const protectedInput = {
      ...baseInput,
      changes: parseNameStatus(`M\t${governancePath}\n`),
    };
    expect(evaluatePolicy(protectedInput).protectedChanges).toEqual([
      governancePath,
    ]);

    const governance = read(governancePath) ?? "";
    expect(() =>
      evaluatePolicy({
        ...protectedInput,
        readHead: (file) =>
          file === governancePath
            ? governance.replace("contents: read", "contents: write")
            : read(file),
      }),
    ).toThrow("semantics differ");

    expect(() =>
      evaluatePolicy({
        ...protectedInput,
        changes: parseNameStatus("M\tpackage.json\n"),
        readHead: (file) =>
          file === "package.json"
            ? qualityPackage.replace("npm run build", "echo skipped")
            : read(file),
      }),
    ).toThrow("canonical closure");

    expect(() =>
      evaluatePolicy({
        ...protectedInput,
        changes: parseNameStatus("M\tpackage.json\n"),
        readHead: (file) =>
          file === "package.json"
            ? qualityPackage.replace(
                "node scripts/package-release.mjs",
                "node scripts/attacker.mjs",
              )
            : read(file),
      }),
    ).toThrow("protected package script changed: release:package");

    expect(() =>
      evaluatePolicy({
        ...protectedInput,
        changes: parseNameStatus("M\tpackage.json\n"),
        readHead: (file) =>
          file === "package.json"
            ? JSON.stringify({
                ...JSON.parse(qualityPackage),
                scripts: {
                  ...JSON.parse(qualityPackage).scripts,
                  preverify: "node attacker.mjs",
                },
              })
            : read(file),
      }),
    ).toThrow("protected package lifecycle hook is denied: preverify");

    expect(() =>
      evaluatePolicy({
        ...protectedInput,
        changes: parseNameStatus("M\t.github/coverage-baseline.json\n"),
        readHead: (file) =>
          file === ".github/coverage-baseline.json"
            ? JSON.stringify({
                lines: 0,
                branches: 1,
                functions: 1,
                statements: 1,
              })
            : read(file),
      }),
    ).toThrow("decrease is denied");

    expect(() =>
      evaluatePolicy({
        ...protectedInput,
        changes: parseNameStatus(
          "R100\ttests/security.test.ts\tsrc/security-example.ts\n",
        ),
      }),
    ).toThrow("test deletion is denied");
  });

  it("pins governance and release executables to the workflow SHA", () => {
    const files = policyFiles();
    const list = () => [...files.keys()];
    const read = (file: string) => files.get(file);

    expect(() =>
      validateTrustedExecutables(
        policy.trustedExecutablePaths,
        read,
        read,
        list,
        list,
      ),
    ).not.toThrow();
    for (const target of [
      "eslint.config.mjs",
      "scripts/coverage-check.mjs",
      "scripts/installer/install-inno-setup.ps1",
      "vitest.config.ts",
    ]) {
      expect(() =>
        validateTrustedExecutables(
          policy.trustedExecutablePaths,
          read,
          (file) => (file === target ? "process.exit(0)\n" : read(file)),
          list,
          list,
        ),
      ).toThrow(`trusted executable differs from workflow SHA: ${target}`);
    }
    expect(() =>
      validateTrustedExecutables(
        policy.trustedExecutablePaths,
        read,
        (file) =>
          file === "scripts/installer/install-inno-setup.ps1"
            ? undefined
            : read(file),
        list,
        list,
      ),
    ).toThrow("trusted executable differs from workflow SHA");
  });

  it("pins dependency declarations and transitive lock resolution", () => {
    const files = policyFiles();
    const read = (file: string) => files.get(file);
    expect(() => validateTrustedToolchain(read, read)).not.toThrow();

    const manifest = JSON.parse(qualityPackage);
    manifest.devDependencies = {
      vitest: "file:tests/fake-vitest",
    };
    expect(() =>
      validateTrustedToolchain(read, (file) =>
        file === "package.json" ? JSON.stringify(manifest) : read(file),
      ),
    ).toThrow("dependency declarations differ from workflow SHA");

    expect(() =>
      validateTrustedToolchain(read, (file) =>
        file === "package-lock.json"
          ? JSON.stringify({
              lockfileVersion: 3,
              packages: {
                "": {},
                "node_modules/vitest": {
                  resolved: "file:tests/fake-vitest",
                },
              },
            })
          : read(file),
      ),
    ).toThrow("package-lock.json differs from workflow SHA");

    const versionOnlyLock = JSON.stringify({
      name: "@cloga/copilot-im-gateway",
      version: "9.9.9",
      lockfileVersion: 3,
      packages: {
        "": {
          name: "@cloga/copilot-im-gateway",
          version: "9.9.9",
        },
      },
    });
    expect(() =>
      validateTrustedToolchain(read, (file) =>
        file === "package-lock.json" ? versionOnlyLock : read(file),
      ),
    ).not.toThrow();
  });

  it("binds pull request trust to the workflow, event, repository, and actor", () => {
    expect(() =>
      validateTrustContext(policy, pullRequestTrust),
    ).not.toThrow();
    expect(() =>
      validateTrustContext(policy, {
        ...pullRequestTrust,
        workflowSha: "abc",
      }),
    ).toThrow("workflow SHA must be a full commit SHA");
    expect(() =>
      validateTrustContext(policy, {
        ...pullRequestTrust,
        eventName: ["pull", "request", "target"].join("_"),
      }),
    ).toThrow("event must be");
    expect(() =>
      validateTrustContext(policy, {
        ...pullRequestTrust,
        repositoryId: "1",
      }),
    ).toThrow("repository ID");
    expect(() =>
      validateTrustContext(policy, {
        ...pullRequestTrust,
        repositoryFullName: "attacker/copilot-im-gateway",
      }),
    ).toThrow("event repository");
    expect(() =>
      validateTrustContext(policy, {
        ...pullRequestTrust,
        baseRef: "release",
      }),
    ).toThrow("base branch must be main");
    expect(() =>
      validateTrustContext(policy, {
        ...pullRequestTrust,
        baseRepoId: "1",
      }),
    ).toThrow("event base");
    expect(() =>
      validateTrustContext(policy, {
        ...pullRequestTrust,
        headRepoFullName: "attacker/copilot-im-gateway",
        headRepoOwner: "attacker",
      }),
    ).toThrow("event head");
    expect(() =>
      validateTrustContext(policy, {
        ...pullRequestTrust,
        headRef: "feature/forged",
      }),
    ).toThrow("head branch");
    expect(() =>
      validateTrustContext(policy, {
        ...pullRequestTrust,
        prAuthor: "attacker",
      }),
    ).toThrow("author");
    expect(() =>
      validateTrustContext(policy, {
        ...pullRequestTrust,
        actor: "maintainer",
      }),
    ).toThrow("actor");

    const dependabotTrust = {
      ...pullRequestTrust,
      headRef: "dependabot/npm_and_yarn/yaml-2.9.0",
      prAuthor: "dependabot[bot]",
      actor: "dependabot[bot]",
    };
    expect(() =>
      validateTrustContext(policy, dependabotTrust),
    ).not.toThrow();
    expect(() =>
      validateTrustContext(policy, {
        ...dependabotTrust,
        actor: "cloga",
      }),
    ).toThrow("automation actor");
  });

  it("validates merge queue trust and applies the same semantic diff policy", () => {
    expect(() =>
      validateTrustContext(policy, mergeGroupTrust),
    ).not.toThrow();
    expect(() =>
      validateTrustContext(policy, {
        ...mergeGroupTrust,
        eventAction: "synchronize",
      }),
    ).toThrow("checks_requested");
    expect(() =>
      validateTrustContext(policy, {
        ...mergeGroupTrust,
        baseRef: "main",
      }),
    ).toThrow("refs/heads/main");
    expect(() =>
      validateTrustContext(policy, {
        ...mergeGroupTrust,
        repositoryId: "1",
      }),
    ).toThrow("repository ID");

    const files = policyFiles();
    expect(
      evaluatePolicy({
        policy,
        changes: parseNameStatus("M\tdocs/security.md\n"),
        trust: mergeGroupTrust,
        readBase: (file) => files.get(file),
        readTrusted: (file) => files.get(file),
        readHead: (file) => files.get(file),
        listTrustedFiles: (directory) =>
          [...files.keys()].filter(
            (file) => !directory || file.startsWith(`${directory}/`),
          ),
        listHeadFiles: (directory) =>
          [...files.keys()].filter(
            (file) => !directory || file.startsWith(`${directory}/`),
          ),
      }),
    ).toEqual({ changedPaths: 1, protectedChanges: [] });
  });

  it("parses workflows fail-closed and validates every action reference", () => {
    const invalidYaml = [
      '"\\u0075ses": actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n',
      "? uses\n: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n",
      "step: &shared\n  run: echo safe\ncopy: *shared\n",
      "step: { uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 }\n",
      "branches: [main]\n",
      "uses: >\n  actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n",
      "name: first\nname: second\n",
      "name: !unsafe value\n",
    ];
    for (const source of invalidYaml) {
      expect(() => parseTrustedWorkflow(source, "unsafe.yml")).toThrow();
    }

    expect(() =>
      validateActionReferences(
        { jobs: { test: { steps: [{ uses: "./local-action" }] } } },
        "unsafe.yml",
      ),
    ).toThrow("full SHA");
    expect(() =>
      validateActionReferences(
        {
          jobs: {
            test: {
              steps: [{ uses: "actions/checkout@v4" }],
            },
          },
        },
        "unsafe.yml",
      ),
    ).toThrow("full SHA");
  });

  it("requires the exact immutable required-workflow AST", () => {
    expect(() =>
      validateWorkflows(
        () => workflowPaths,
        (workflow) => readRepositoryFile(workflow),
      ),
    ).not.toThrow();

    const governance = readRepositoryFile(governancePath);
    const parsedGovernance = parseTrustedWorkflow(governance, governancePath);
    expect(parsedGovernance.on).toEqual({
      pull_request: {
        types: [
          "opened",
          "synchronize",
          "reopened",
          "ready_for_review",
          "edited",
        ],
      },
      merge_group: {
        types: ["checks_requested"],
      },
    });
    expect(parsedGovernance.permissions).toEqual({ contents: "read" });
    const requiredPolicy = (
      parsedGovernance.jobs as Record<
        string,
        { name: string; steps: Array<Record<string, unknown>> }
      >
    )["required-policy"];
    expect(requiredPolicy?.name).toBe("Required policy");
    expect(requiredPolicy?.steps[0]).toMatchObject({
      name: "Validate trusted event context",
    });
    expect(requiredPolicy?.steps[1]).toMatchObject({
      name: "Check out required workflow source",
      with: {
        ref: "${{ github.workflow_sha }}",
        "fetch-depth": 1,
        "persist-credentials": false,
      },
    });

    const oldGovernancePath = `.github/workflows/${["governance", ".yml"].join("")}`;
    expect(existsSync(path.join(process.cwd(), oldGovernancePath))).toBe(false);
    for (const obsolete of [
      ["manual", "governance"].join("-"),
      ["label", "ed"].join(""),
      ["un", "label", "ed"].join(""),
      ["prove", "nance"].join(""),
      "actions/upload-artifact",
      ["gh", "api"].join(" "),
      `/${["collab", "orators"].join("")}/`,
      ["pull", "request", "target"].join("_"),
    ]) {
      expect(governance).not.toContain(obsolete);
    }

    const targetTrigger = ["pull", "request", "target"].join("_");
    const tampered = [
      governance.replace(
        "ref: ${{ github.workflow_sha }}",
        "ref: ${{ github.event.pull_request.head.sha }}",
      ),
      governance.replace(
        "ref: ${{ github.workflow_sha }}",
        "ref: ${{ github.event.pull_request.base.sha }}",
      ),
      governance.replaceAll(
        "WORKFLOW_SHA: ${{ github.workflow_sha }}",
        "WORKFLOW_SHA: ${{ github.sha }}",
      ),
      governance.replaceAll(
        '--workflow-sha "$WORKFLOW_SHA"',
        '--event-name "$EVENT_NAME"',
      ),
      governance.replace("contents: read", "contents: write"),
      governance.replace(
        /permissions:\r?\n {2}contents: read/u,
        "permissions:\n  actions: read\n  contents: read",
      ),
      governance.replace(
        "      - name: Evaluate required policy",
        '      - name: Execute untrusted head\n        run: git checkout "$PR_HEAD_SHA" && node scripts/governance-check.mjs\n      - name: Evaluate required policy',
      ),
      governance.replace(
        / {2}pull_request:\r?\n/u,
        `  ${targetTrigger}:\n`,
      ),
      governance.replace(
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "actions/checkout@v4",
      ),
      governance.replace(
        "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
        "actions/setup-node@v4",
      ),
    ];
    for (const source of tampered) {
      expect(() =>
        validateWorkflows(
          () => workflowPaths,
          (workflow) =>
            workflow === governancePath
              ? source
              : readRepositoryFile(workflow),
        ),
      ).toThrow();
    }

    const releasePath = ".github/workflows/release.yml";
    const weakenedRelease = readRepositoryFile(releasePath).replace(
      "git merge-base --is-ancestor HEAD origin/main",
      "git status",
    );
    expect(() =>
      validateWorkflows(
        () => workflowPaths,
        (workflow) =>
          workflow === releasePath
            ? weakenedRelease
            : readRepositoryFile(workflow),
      ),
    ).toThrow("semantics differ");
  });

  it("contains no obsolete approval or remote authorization implementation", () => {
    const implementation = [
      governancePath,
      "scripts/governance-check.mjs",
      "scripts/policy-check.mjs",
      "scripts/workflow-policy.mjs",
    ]
      .map((file) => readRepositoryFile(file))
      .join("\n");
    for (const obsolete of [
      ["manual", "governance"].join("-"),
      ["prove", "nance"].join(""),
      `/${["collab", "orators"].join("")}/`,
      ["gh", "api"].join(" "),
    ]) {
      expect(implementation).not.toContain(obsolete);
    }
  });

  it("documents the immutable required-workflow trust root", () => {
    const documentationPaths = [
      "AGENTS.md",
      "docs/security.md",
      "docs/development.md",
      "docs/change-impact.md",
      ".github/pull_request_template.md",
    ];
    const documentation = new Map(
      documentationPaths.map((file) => [file, readRepositoryFile(file)]),
    );
    const corpus = [...documentation.values()].join("\n");
    expect(corpus).not.toContain(["manual", "governance"].join("-"));
    expect(documentation.get("docs/security.md")).toContain(repositoryFullName);
    expect(documentation.get("docs/security.md")).toContain(repositoryId);
    expect(documentation.get("docs/security.md")).toContain(governancePath);
    expect(documentation.get("docs/security.md")).toContain("`workflows`");
    expect(documentation.get("docs/security.md")).toContain(
      "`github.workflow_sha`",
    );
    expect(documentation.get("docs/security.md")).toContain(
      "<merge-commit-sha>",
    );
  });
});

function policyFiles() {
  const files = new Map<string, string>([
    ["package.json", qualityPackage],
    [
      "package-lock.json",
      JSON.stringify({
        name: "@cloga/copilot-im-gateway",
        version: "0.1.2",
        lockfileVersion: 3,
        packages: {
          "": {
            name: "@cloga/copilot-im-gateway",
            version: "0.1.2",
          },
        },
      }),
    ],
    [".github/coverage-baseline.json", coverageBaseline],
    ["src/core/security.ts", "export const secure = true;\n"],
    ["tests/security.test.ts", "test('secure', () => {});\n"],
    ["docs/security.md", "# Security\n"],
    ["eslint.config.mjs", "export default [];\n"],
    ["scripts/coverage-check.mjs", "export const coverage = true;\n"],
    [
      "scripts/installer/install-inno-setup.ps1",
      'Write-Output "trusted"\n',
    ],
    ["tsconfig.build.json", '{"extends":"./tsconfig.json"}\n'],
    ["tsconfig.json", '{"compilerOptions":{"strict":true}}\n'],
    ["vitest.config.ts", "export default {};\n"],
  ]);
  for (const workflow of workflowPaths) {
    files.set(workflow, readRepositoryFile(workflow));
  }
  return files;
}

function readRepositoryFile(file: string) {
  return readFileSync(path.join(process.cwd(), ...file.split("/")), "utf8");
}
