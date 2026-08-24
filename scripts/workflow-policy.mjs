import { isDeepStrictEqual } from "node:util";
import {
  isAlias,
  isMap,
  isScalar,
  isSeq,
  parseDocument,
  visit,
} from "yaml";

const checkoutAction =
  "actions/checkout@11d5960a326750d5838078e36cf38b85af677262";
const setupNodeAction =
  "actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020";
const uploadArtifactAction =
  "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02";
const protectedBaseValidationScript =
  'test "$BASE_REF" = "main" && test "$BASE_REPO_FULL_NAME" = "cloga/copilot-im-gateway" && test "$REPOSITORY" = "cloga/copilot-im-gateway"';

const governanceApprovalScript = `approved=false
if [[ "$ACTION" == "labeled" && "$LABEL" == "manual-governance" && "$EVENT_ACTOR" != "$PR_AUTHOR" ]]; then
  permission="$(gh api "repos/$REPOSITORY/collaborators/$EVENT_ACTOR/permission" --jq .permission)"
  if [[ "$permission" == "admin" || "$permission" == "maintain" || "$permission" == "write" ]]; then
    approved=true
  fi
fi
echo "approved=$approved" >> "$GITHUB_OUTPUT"
`;

const governancePrepareProvenanceScript = `expected_actor=""
if [[ "$HEAD_REPO_FULL_NAME" == "$REPOSITORY" && "$HEAD_REPO_OWNER" == "cloga" ]]; then
  if [[ "$HEAD_REF" == cloga/* && "$PR_AUTHOR" == "cloga" ]]; then
    expected_actor="cloga"
  elif [[ "$HEAD_REF" == dependabot/* && "$PR_AUTHOR" == "dependabot[bot]" ]]; then
    expected_actor="dependabot[bot]"
  fi
fi
if [[ -z "$expected_actor" || "$EVENT_ACTOR" != "$expected_actor" ]]; then
  exit 1
fi
mkdir provenance
printf '%s\\n' "$HEAD_SHA:$expected_actor:$PR_NUMBER" > provenance/head.txt
`;

const governanceProvenanceScript = `verified=false
expected_actor=""
if [[ "$HEAD_REPO_FULL_NAME" == "$REPOSITORY" && "$HEAD_REPO_OWNER" == "cloga" ]]; then
  if [[ "$HEAD_REF" == cloga/* && "$PR_AUTHOR" == "cloga" ]]; then
    expected_actor="cloga"
  elif [[ "$HEAD_REF" == dependabot/* && "$PR_AUTHOR" == "dependabot[bot]" ]]; then
    expected_actor="dependabot[bot]"
  fi
fi
export EXPECTED_ACTOR="$expected_actor"
if [[ -n "$expected_actor" ]]; then
  if [[ "$EVENT_ACTION" == "opened" || "$EVENT_ACTION" == "synchronize" ]]; then
    if [[ "$EVENT_ACTOR" == "$expected_actor" ]]; then
      verified=true
    fi
  else
    mapfile -t candidates < <(gh api "repos/$REPOSITORY/actions/artifacts?name=governance-head-$HEAD_SHA&per_page=100" --jq '.artifacts[] | select(.expired == false) | "\\(.id) \\(.workflow_run.id)"')
    for candidate in "\${candidates[@]}"; do
      read -r artifact_id run_id <<< "$candidate"
      if [[ ! "$artifact_id" =~ ^[0-9]+$ || ! "$run_id" =~ ^[0-9]+$ ]]; then
        continue
      fi
      if ! gh api "repos/$REPOSITORY/actions/runs/$run_id" | node -e 'const fs=require("node:fs");const run=JSON.parse(fs.readFileSync(0,"utf8"));const valid=run.name==="Governance"&&run.path===".github/workflows/governance.yml"&&run.event==="pull_request_target"&&run.actor?.login===process.env.EXPECTED_ACTOR&&run.repository?.full_name===process.env.REPOSITORY;process.exit(valid?0:1)'; then
        continue
      fi
      artifact_zip="$RUNNER_TEMP/governance-provenance-$artifact_id.zip"
      gh api "repos/$REPOSITORY/actions/artifacts/$artifact_id/zip" > "$artifact_zip"
      if [[ "$(unzip -Z1 "$artifact_zip")" == "head.txt" && "$(unzip -p "$artifact_zip" head.txt)" == "$HEAD_SHA:$expected_actor:$PR_NUMBER" ]]; then
        verified=true
        break
      fi
    done
  fi
fi
echo "verified=$verified" >> "$GITHUB_OUTPUT"
`;

const governanceExpected = {
  name: "Governance",
  on: {
    pull_request_target: {
      types: [
        "opened",
        "synchronize",
        "edited",
        "reopened",
        "ready_for_review",
        "labeled",
        "unlabeled",
      ],
    },
  },
  permissions: {
    actions: "read",
    contents: "read",
  },
  jobs: {
    "protected-policy": {
      name: "Protected policy",
      "runs-on": "ubuntu-latest",
      steps: [
        {
          name: "Validate protected base target",
          env: {
            BASE_REF: "${{ github.event.pull_request.base.ref }}",
            BASE_REPO_FULL_NAME:
              "${{ github.event.pull_request.base.repo.full_name }}",
            REPOSITORY: "${{ github.repository }}",
          },
          shell: "bash",
          run: protectedBaseValidationScript,
        },
        {
          name: "Check out protected base",
          uses: checkoutAction,
          with: {
            ref: "${{ github.event.pull_request.base.sha }}",
            "fetch-depth": 1,
            "persist-credentials": false,
          },
        },
        {
          name: "Set up protected base Node",
          uses: setupNodeAction,
          with: {
            "node-version": "24.11.1",
            cache: "npm",
          },
        },
        {
          name: "Install protected base dependencies",
          run: "npm ci --ignore-scripts --no-audit --no-fund",
        },
        {
          name: "Fetch untrusted head as git data only",
          env: {
            PR_NUMBER: "${{ github.event.pull_request.number }}",
          },
          run: 'git fetch --no-tags --depth=1 origin "refs/pull/${PR_NUMBER}/head"',
        },
        {
          name: "Prepare exact head provenance",
          if: "github.event.action == 'opened' || github.event.action == 'synchronize'",
          env: {
            EVENT_ACTOR: "${{ github.actor }}",
            HEAD_REF: "${{ github.event.pull_request.head.ref }}",
            HEAD_REPO_FULL_NAME:
              "${{ github.event.pull_request.head.repo.full_name }}",
            HEAD_REPO_OWNER:
              "${{ github.event.pull_request.head.repo.owner.login }}",
            HEAD_SHA: "${{ github.event.pull_request.head.sha }}",
            PR_AUTHOR: "${{ github.event.pull_request.user.login }}",
            PR_NUMBER: "${{ github.event.pull_request.number }}",
            REPOSITORY: "${{ github.repository }}",
          },
          shell: "bash",
          run: governancePrepareProvenanceScript,
        },
        {
          name: "Upload exact head provenance",
          if: "github.event.action == 'opened' || github.event.action == 'synchronize'",
          uses: uploadArtifactAction,
          with: {
            name: "governance-head-${{ github.event.pull_request.head.sha }}",
            path: "provenance/head.txt",
            "if-no-files-found": "error",
            "retention-days": 90,
          },
        },
        {
          name: "Validate exact head provenance",
          id: "provenance",
          env: {
            GH_TOKEN: "${{ github.token }}",
            EVENT_ACTION: "${{ github.event.action }}",
            EVENT_ACTOR: "${{ github.actor }}",
            HEAD_REF: "${{ github.event.pull_request.head.ref }}",
            HEAD_REPO_FULL_NAME:
              "${{ github.event.pull_request.head.repo.full_name }}",
            HEAD_REPO_OWNER:
              "${{ github.event.pull_request.head.repo.owner.login }}",
            HEAD_SHA: "${{ github.event.pull_request.head.sha }}",
            PR_AUTHOR: "${{ github.event.pull_request.user.login }}",
            PR_NUMBER: "${{ github.event.pull_request.number }}",
            REPOSITORY: "${{ github.repository }}",
          },
          shell: "bash",
          run: governanceProvenanceScript,
        },
        {
          name: "Validate fresh maintainer approval",
          id: "approval",
          env: {
            ACTION: "${{ github.event.action }}",
            EVENT_ACTOR: "${{ github.actor }}",
            GH_TOKEN: "${{ github.token }}",
            LABEL: "${{ github.event.label.name }}",
            PR_AUTHOR: "${{ github.event.pull_request.user.login }}",
            REPOSITORY: "${{ github.repository }}",
          },
          shell: "bash",
          run: governanceApprovalScript,
        },
        {
          name: "Evaluate protected base policy",
          env: {
            BASE_REF: "${{ github.event.pull_request.base.ref }}",
            BASE_REPO_FULL_NAME:
              "${{ github.event.pull_request.base.repo.full_name }}",
            BASE_SHA: "${{ github.event.pull_request.base.sha }}",
            EVENT_ACTION: "${{ github.event.action }}",
            EVENT_ACTOR: "${{ github.actor }}",
            HEAD_REF: "${{ github.event.pull_request.head.ref }}",
            HEAD_REPO_FULL_NAME:
              "${{ github.event.pull_request.head.repo.full_name }}",
            HEAD_REPO_OWNER:
              "${{ github.event.pull_request.head.repo.owner.login }}",
            HEAD_SHA: "${{ github.event.pull_request.head.sha }}",
            HEAD_PROVENANCE_VERIFIED:
              "${{ steps.provenance.outputs.verified }}",
            MANUAL_GOVERNANCE_APPROVED:
              "${{ steps.approval.outputs.approved }}",
            PR_AUTHOR: "${{ github.event.pull_request.user.login }}",
          },
          run: 'node scripts/governance-check.mjs --base "$BASE_SHA" --base-ref "$BASE_REF" --base-repo-full-name "$BASE_REPO_FULL_NAME" --head "$HEAD_SHA" --head-ref "$HEAD_REF" --head-repo-owner "$HEAD_REPO_OWNER" --head-repo-full-name "$HEAD_REPO_FULL_NAME" --pr-author "$PR_AUTHOR" --event-action "$EVENT_ACTION" --event-actor "$EVENT_ACTOR" --head-provenance-verified "$HEAD_PROVENANCE_VERIFIED" --manual-governance-approved "$MANUAL_GOVERNANCE_APPROVED"',
        },
      ],
    },
  },
};

const ciExpected = {
  name: "CI",
  on: {
    pull_request: null,
    push: {
      branches: ["main"],
    },
  },
  permissions: {
    contents: "read",
  },
  jobs: {
    verify: {
      name: "Verify (${{ matrix.os }}, Node ${{ matrix.node }})",
      strategy: {
        "fail-fast": false,
        matrix: {
          os: ["ubuntu-latest", "windows-latest"],
          node: ["22.13.0", "24.11.1"],
        },
      },
      "runs-on": "${{ matrix.os }}",
      steps: [
        {
          uses: checkoutAction,
          with: {
            "fetch-depth": 0,
            "persist-credentials": false,
          },
        },
        {
          uses: setupNodeAction,
          with: {
            "node-version": "${{ matrix.node }}",
            cache: "npm",
          },
        },
        {
          run: "npm ci --ignore-scripts --no-audit --no-fund",
        },
        {
          run: "npm run verify",
          env: {
            AGENT_POLICY_HEAD_REF:
              "${{ github.head_ref || github.ref_name }}",
          },
        },
      ],
    },
    "windows-installer": {
      name: "Windows installer smoke",
      "runs-on": "windows-latest",
      steps: [
        {
          uses: checkoutAction,
          with: {
            "persist-credentials": false,
          },
        },
        {
          uses: setupNodeAction,
          with: {
            "node-version": "24.11.1",
            cache: "npm",
          },
        },
        {
          run: "npm ci --ignore-scripts --no-audit --no-fund",
        },
        {
          run: "npm run build",
        },
        {
          name: "Install pinned Inno Setup",
          shell: "pwsh",
          run: `$compiler = & .\\scripts\\installer\\install-inno-setup.ps1
"ISCC_PATH=$compiler" >> $env:GITHUB_ENV
`,
        },
        {
          run: "npm run release:installer",
        },
        {
          run: "npm run release:installer:smoke",
        },
      ],
    },
  },
};

const releaseExpected = {
  name: "Release",
  on: {
    push: {
      tags: ["v*"],
    },
  },
  permissions: {
    contents: "read",
  },
  jobs: {
    release: {
      permissions: {
        contents: "write",
      },
      "runs-on": "windows-latest",
      steps: [
        {
          uses: checkoutAction,
          with: {
            "fetch-depth": 0,
            "persist-credentials": false,
          },
        },
        {
          name: "Require tag commit on main",
          shell: "pwsh",
          run: `git fetch --no-tags origin main:refs/remotes/origin/main
git merge-base --is-ancestor HEAD origin/main
if ($LASTEXITCODE -ne 0) {
  throw "Release tag commit must be reachable from origin/main."
}
`,
        },
        {
          uses: setupNodeAction,
          with: {
            "node-version": "24.11.1",
            cache: "npm",
          },
        },
        {
          name: "Validate release tag",
          shell: "pwsh",
          run: `$version = node --print "require('./package.json').version"
if ($env:GITHUB_REF_NAME -ne "v$version") {
  throw "Tag $env:GITHUB_REF_NAME must match package version v$version."
}
`,
        },
        {
          run: "npm ci --ignore-scripts --no-audit --no-fund",
        },
        {
          run: "npm run verify",
        },
        {
          run: "npm run release:package",
        },
        {
          run: "npm run release:validate",
        },
        {
          name: "Install pinned Inno Setup",
          shell: "pwsh",
          run: `$compiler = & .\\scripts\\installer\\install-inno-setup.ps1
"ISCC_PATH=$compiler" >> $env:GITHUB_ENV
`,
        },
        {
          run: "npm run release:installer",
        },
        {
          run: "npm run release:installer:smoke",
        },
        {
          uses: uploadArtifactAction,
          with: {
            name: "copilot-im-gateway-${{ github.ref_name }}",
            path: `release/*.tgz
release/*.zip
release/*.exe
release/*.sha256
`,
            "if-no-files-found": "error",
          },
        },
        {
          name: "Publish GitHub Release",
          env: {
            GH_TOKEN: "${{ github.token }}",
          },
          shell: "pwsh",
          run: `gh release create "$env:GITHUB_REF_NAME" (Get-ChildItem release\\*.tgz, release\\*.zip, release\\*.exe, release\\*.sha256).FullName \`
  --verify-tag \`
  --generate-notes \`
  --title "Copilot IM Gateway $env:GITHUB_REF_NAME"
`,
        },
      ],
    },
  },
};

/** @type {Map<string, unknown>} */
const expectedWorkflows = new Map();
expectedWorkflows.set(".github/workflows/ci.yml", ciExpected);
expectedWorkflows.set(
  ".github/workflows/governance.yml",
  governanceExpected,
);
expectedWorkflows.set(".github/workflows/release.yml", releaseExpected);

/**
 * @param {string} source
 * @param {string} path
 */
export function parseTrustedWorkflow(source, path) {
  const document = parseDocument(source, {
    customTags: [],
    keepSourceTokens: true,
    merge: false,
    schema: "core",
    uniqueKeys: true,
  });
  if (document.errors.length > 0 || document.warnings.length > 0) {
    throw new Error(
      `Workflow YAML is invalid in ${path}: ${[
        ...document.errors,
        ...document.warnings,
      ]
        .map((error) => error.message)
        .join("; ")}`,
    );
  }

  visit(document, {
    Node(_key, node) {
      if (isAlias(node) || node.anchor !== undefined) {
        throw new Error(`Workflow aliases and anchors are denied in ${path}`);
      }
      if (node.tag !== undefined) {
        throw new Error(`Workflow custom tags are denied in ${path}`);
      }
      if ((isMap(node) || isSeq(node)) && node.flow === true) {
        throw new Error(`Workflow flow collections are denied in ${path}`);
      }
      if (isMap(node)) {
        const token = node.srcToken;
        if (
          token?.type !== "block-map" ||
          token.items.some((item) => item.explicitKey === true)
        ) {
          throw new Error(
            `Workflow mappings must use canonical block keys in ${path}`,
          );
        }
        for (const pair of node.items) {
          if (
            !isScalar(pair.key) ||
            pair.key.type !== "PLAIN" ||
            typeof pair.key.value !== "string"
          ) {
            throw new Error(
              `Workflow mapping keys must be plain strings in ${path}`,
            );
          }
        }
      }
      if (
        isScalar(node) &&
        node.type === "BLOCK_FOLDED"
      ) {
        throw new Error(`Workflow folded scalar values are denied in ${path}`);
      }
    },
  });

  const value = document.toJS({ maxAliasCount: 0 });
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Workflow root must be a mapping in ${path}`);
  }
  return /** @type {Record<string, unknown>} */ (value);
}

/**
 * @param {(path: string) => string[]} listHeadFiles
 * @param {(path: string) => string | undefined} readHead
 */
export function validateWorkflows(listHeadFiles, readHead) {
  const paths = listHeadFiles(".github/workflows").sort();
  const expectedPaths = [...expectedWorkflows.keys()].sort();
  if (!isDeepStrictEqual(paths, expectedPaths)) {
    throw new Error("Workflow file set differs from the protected allowlist");
  }

  for (const path of paths) {
    const source = readHead(path);
    if (source === undefined) {
      throw new Error(`Workflow is missing: ${path}`);
    }
    const workflow = parseTrustedWorkflow(source, path);
    validateActionReferences(workflow, path);
    if (!isDeepStrictEqual(workflow, expectedWorkflows.get(path))) {
      throw new Error(`Workflow semantics differ from protected policy: ${path}`);
    }
  }
}

/** @param {unknown} value @param {string} path */
export function validateActionReferences(value, path) {
  if (Array.isArray(value)) {
    for (const entry of value) {
      validateActionReferences(entry, path);
    }
    return;
  }
  if (value === null || typeof value !== "object") {
    return;
  }
  for (const [key, entry] of Object.entries(value)) {
    if (key === "uses") {
      if (
        typeof entry !== "string" ||
        !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[a-f0-9]{40}$/u.test(entry)
      ) {
        throw new Error(
          `Workflow action must be owner/repository pinned to a full SHA in ${path}`,
        );
      }
    } else {
      validateActionReferences(entry, path);
    }
  }
}
