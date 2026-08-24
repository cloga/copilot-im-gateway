import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { assertCoverageFloor } from "../scripts/coverage-check.mjs";
import {
  evaluatePolicy,
  validateCoverageBaseline,
  validatePullRequestIdentity,
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

const qualityPackage = JSON.stringify({
  scripts: {
    "audit:check": "npm audit --audit-level=high",
    check: "npm run verify",
    "coverage:check": "node scripts/coverage-check.mjs",
    "policy:check": "node scripts/policy-check.mjs",
    "release:verify": "node scripts/verify-release.mjs",
    "test:coverage": "vitest run --coverage",
    verify:
      "npm run lint && npm run typecheck && npm run test:coverage && npm run coverage:check && npm run build && npm run audit:check && npm run policy:check && npm run release:verify",
  },
});

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

  it("requires fresh approval for protected paths and tests for runtime changes", () => {
    const policy = {
      defaultBranch: "main",
      repositoryFullName: "cloga/copilot-im-gateway",
      branchAccount: "cloga",
      branchAccountPrefix: "cloga/",
      automationAccount: "dependabot[bot]",
      automationBranchPrefixes: ["dependabot/"],
      allowedPaths: ["src/**", "tests/**", ".github/**", "package.json"],
      deniedPaths: ["**/.env"],
      protectedPaths: [".github/**"],
      runtimeSecurityPaths: ["src/**"],
      regressionTestPaths: ["tests/**/*.test.ts"],
      productCodePaths: ["src/**"],
      forbiddenProductPatterns: ["--acp"],
      forbiddenTestPatterns: [["ilinkai", "weixin.qq.com"].join(".")],
      architectureAssertions: [],
    };
    const files = new Map([
      ["package.json", qualityPackage],
      [
        ".github/coverage-baseline.json",
        JSON.stringify({
          lines: 1,
          branches: 1,
          functions: 1,
          statements: 1,
        }),
      ],
      ["src/core/security.ts", "export const secure = true;\n"],
      ["tests/security.test.ts", "test('secure', () => {});\n"],
    ]);
    for (const workflow of [
      ".github/workflows/ci.yml",
      ".github/workflows/governance.yml",
      ".github/workflows/release.yml",
    ]) {
      files.set(
        workflow,
        readFileSync(path.join(process.cwd(), ...workflow.split("/")), "utf8"),
      );
    }
    const read = (file: string) => files.get(file);
    const list = (directory: string) =>
      [...files.keys()].filter(
        (file) => !directory || file.startsWith(`${directory}/`),
      );

    expect(() =>
      evaluatePolicy({
        policy,
        changes: parseNameStatus("M\tsrc/core/security.ts\n"),
        headRef: "cloga/secure-change",
        identity: clogaIdentity,
        manualGovernanceApproved: false,
        readBase: read,
        readHead: read,
        listHeadFiles: list,
      }),
    ).toThrow("require a regression test");

    const protectedInput = {
      policy,
      changes: parseNameStatus("M\t.github/workflows/ci.yml\n"),
      headRef: "cloga/governance",
      identity: clogaIdentity,
      readBase: read,
      readHead: read,
      listHeadFiles: list,
    };
    expect(() =>
      evaluatePolicy({
        ...protectedInput,
        manualGovernanceApproved: false,
      }),
    ).toThrow("fresh manual-governance approval");
    expect(
      evaluatePolicy({
        ...protectedInput,
        manualGovernanceApproved: true,
      }).protectedChanges,
    ).toEqual([".github/workflows/ci.yml"]);

    expect(() =>
      evaluatePolicy({
        ...protectedInput,
        changes: parseNameStatus(
          "R100\ttests/security.test.ts\tsrc/security-example.ts\n",
        ),
        manualGovernanceApproved: true,
      }),
    ).toThrow("test deletion is denied");
  });

  it("binds branch policy to repository and event identities", () => {
    const policy = {
      defaultBranch: "main",
      repositoryFullName: "cloga/copilot-im-gateway",
      branchAccount: "cloga",
      branchAccountPrefix: "cloga/",
      automationAccount: "dependabot[bot]",
      automationBranchPrefixes: ["dependabot/"],
    };
    expect(() =>
      validatePullRequestIdentity(
        policy,
        "cloga/agentic-governance",
        clogaIdentity,
      ),
    ).not.toThrow();
    expect(() =>
      validatePullRequestIdentity(policy, "cloga/agentic-governance", {
        ...clogaIdentity,
        baseRef: "release",
        eventAction: "edited",
      }),
    ).toThrow("base branch must be main");
    expect(() =>
      validatePullRequestIdentity(policy, "cloga/agentic-governance", {
        ...clogaIdentity,
        baseRepoFullName: "attacker/copilot-im-gateway",
        eventAction: "edited",
      }),
    ).toThrow("base must be the protected repository");
    expect(() =>
      validatePullRequestIdentity(
        { ...policy, defaultBranch: "release" },
        "cloga/agentic-governance",
        {
          ...clogaIdentity,
          baseRef: "release",
          eventAction: "edited",
        },
      ),
    ).toThrow("policy default branch must be main");
    expect(() =>
      validatePullRequestIdentity(policy, "cloga/forged", {
        ...clogaIdentity,
        headRepoFullName: "attacker/copilot-im-gateway",
        headRepoOwner: "attacker",
      }),
    ).toThrow("protected repository");
    expect(() =>
      validatePullRequestIdentity(policy, "cloga/forged", {
        ...clogaIdentity,
        prAuthor: "attacker",
      }),
    ).toThrow("author");
    expect(() =>
      validatePullRequestIdentity(policy, "dependabot/npm_and_yarn/yaml-2.9.0", {
        ...clogaIdentity,
        prAuthor: "dependabot[bot]",
        eventActor: "dependabot[bot]",
      }),
    ).not.toThrow();
    expect(() =>
      validatePullRequestIdentity(policy, "dependabot/forged", clogaIdentity),
    ).toThrow("automation author");
    expect(() =>
      validatePullRequestIdentity(policy, "dependabot/npm_and_yarn/yaml-2.9.0", {
        ...clogaIdentity,
        prAuthor: "dependabot[bot]",
        eventAction: "labeled",
        eventActor: "maintainer",
        headProvenanceVerified: true,
      }),
    ).not.toThrow();
    expect(() =>
      validatePullRequestIdentity(policy, "dependabot/npm_and_yarn/yaml-2.9.0", {
        ...clogaIdentity,
        prAuthor: "dependabot[bot]",
        eventAction: "labeled",
        eventActor: "maintainer",
        headProvenanceVerified: false,
      }),
    ).toThrow("trusted authoring-event provenance");
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
              steps: [
                {
                  uses: "actions/checkout@v4",
                },
              ],
            },
          },
        },
        "unsafe.yml",
      ),
    ).toThrow("full SHA");

    const workflows = [
      ".github/workflows/ci.yml",
      ".github/workflows/governance.yml",
      ".github/workflows/release.yml",
    ];
    expect(() =>
      validateWorkflows(
        () => workflows,
        (workflow) =>
          readFileSync(
            path.join(process.cwd(), ...workflow.split("/")),
            "utf8",
          ),
      ),
    ).not.toThrow();

    const releasePath = ".github/workflows/release.yml";
    const release = readFileSync(
      path.join(process.cwd(), ...releasePath.split("/")),
      "utf8",
    );
    expect(() =>
      validateWorkflows(
        () => workflows,
        (workflow) =>
          workflow === releasePath
            ? release.replace(
                "git merge-base --is-ancestor HEAD origin/main",
                "git status",
              )
            : readFileSync(
                path.join(process.cwd(), ...workflow.split("/")),
                "utf8",
              ),
      ),
    ).toThrow("semantics differ");

    const governancePath = ".github/workflows/governance.yml";
    const governance = readFileSync(
      path.join(process.cwd(), ...governancePath.split("/")),
      "utf8",
    );
    expect(() =>
      validateWorkflows(
        () => workflows,
        (workflow) =>
          workflow === governancePath
            ? governance.replace(
                "name: Evaluate protected base policy",
                "name: Execute head code\n        run: node ../head/script.mjs\n      - name: Evaluate protected base policy",
              )
            : readFileSync(
                path.join(process.cwd(), ...workflow.split("/")),
                "utf8",
              ),
      ),
    ).toThrow("semantics differ");
  });
});

const clogaIdentity = {
  baseRef: "main",
  baseRepoFullName: "cloga/copilot-im-gateway",
  headRepoOwner: "cloga",
  headRepoFullName: "cloga/copilot-im-gateway",
  prAuthor: "cloga",
  eventAction: "synchronize",
  eventActor: "cloga",
  headProvenanceVerified: true,
};
