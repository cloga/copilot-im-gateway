import {
  type ChildProcess,
  type SpawnSyncReturns,
  spawn,
  spawnSync,
} from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { realpathSync } from "node:fs";
import {
  mkdir,
  mkdtemp,
  link,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  assertBuildOutput,
  createDeterministicZip,
  writeChecksum,
} from "../scripts/package-release.mjs";
import {
  collectFilesystemEsmClosure,
  daemonRuntimeEntrypoint,
  daemonRuntimeManifest,
  esmClosureManifestVersion,
  findRelativeEsmSpecifiers,
  parseEsmClosureManifest,
  writeEsmClosureManifest,
} from "../scripts/release/esm-closure.mjs";
import {
  requiredEntries,
  validateReleaseArchive,
} from "../scripts/validate-release.mjs";

const slowPowerShellTimeout = 45_000;

function expectSpawnCompleted(result: SpawnSyncReturns<string>): void {
  expect(result.error).toBeUndefined();
  expect(result.signal).toBeNull();
}

async function createReleaseFixture(
  stage: string,
  omittedEntry?: string,
): Promise<void> {
  for (const entry of requiredEntries) {
    const relativePath = entry.replace(/^package\//u, "");
    if (
      relativePath === daemonRuntimeManifest ||
      relativePath === omittedEntry
    ) {
      continue;
    }
    const destination = path.join(stage, ...relativePath.split("/"));
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, `fixture:${relativePath}\n`, "utf8");
  }
  const runtimeSources = new Map([
    [
      "dist/daemon/main.js",
      [
        'import "./store.js";',
        'import "../channels/weixin/adapter.js";',
        "",
      ].join("\n"),
    ],
    ["dist/daemon/store.js", "export const store = true;\n"],
    ["dist/channels/weixin/adapter.js", "export const adapter = true;\n"],
  ]);
  for (const [relativePath, source] of runtimeSources) {
    if (relativePath === omittedEntry) {
      continue;
    }
    const destination = path.join(stage, ...relativePath.split("/"));
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, source, "utf8");
  }
  await writeEsmClosureManifest(
    stage,
    path.join(stage, daemonRuntimeManifest),
  );
}

async function rewriteClosureManifest(
  stage: string,
  changes: {
    entrypoint?: string;
    files?: string[];
    version?: number;
  },
): Promise<void> {
  const manifestPath = path.join(stage, daemonRuntimeManifest);
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as {
    entrypoint: string;
    files: string[];
    version: number;
  };
  await writeFile(
    manifestPath,
    `${JSON.stringify({ ...manifest, ...changes }, null, 2)}\n`,
    "utf8",
  );
}

async function availablePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("Test listener did not receive a TCP port.");
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
  return address.port;
}

async function waitForFile(filePath: string): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    try {
      await readFile(filePath);
      return;
    } catch (error) {
      if (
        !(error instanceof Error) ||
        !("code" in error) ||
        error.code !== "ENOENT"
      ) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
  throw new Error(`Timed out waiting for ${filePath}.`);
}

async function stopTestProcess(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  const exited = new Promise<void>((resolve) => {
    child.once("exit", () => resolve());
  });
  child.kill();
  await exited;
}

describe("release packaging", () => {
  it("keeps the v2 daemon and extension in one release compatibility unit", async () => {
    expect(requiredEntries).toEqual(
      expect.arrayContaining([
        "package/dist/daemon/main.js",
        `package/${daemonRuntimeManifest}`,
        "package/.github/extensions/im-gateway/gateway-client.mjs",
        "package/.github/extensions/im-gateway/extension-runtime.mjs",
      ]),
    );
    const root = path.resolve(import.meta.dirname, "..");
    const daemon = await readFile(
      path.join(root, "src", "daemon", "http-server.ts"),
      "utf8",
    );
    const client = await readFile(
      path.join(
        root,
        ".github",
        "extensions",
        "im-gateway",
        "gateway-client.mjs",
      ),
      "utf8",
    );
    for (const capability of [
      "account-scoped-routing",
      "sender-bound-routing",
      "operation-bound-approvals",
      "reservation-ownership",
    ]) {
      expect(daemon).toContain(capability);
      expect(client).toContain(capability);
    }
    expect(daemon).toContain("gatewayApiVersion = 2");
    expect(client).toContain("supportedGatewayApiVersion = 2");
  });

  it("finds static imports, re-exports, and literal dynamic imports", () => {
    expect(
      findRelativeEsmSpecifiers(`
        import "./side-effect.js";
        import value from "../value.js";
        export { result } from "./result.js";
        export * from "./all.js";
        const lazy = import("./lazy.js", { with: { type: "json" } });
        const ignored = import(packageName);
      `),
    ).toEqual([
      "../value.js",
      "./all.js",
      "./lazy.js",
      "./result.js",
      "./side-effect.js",
    ]);
  });

  it("requires the supported canonical daemon closure manifest contract", () => {
    const valid = {
      version: esmClosureManifestVersion,
      entrypoint: daemonRuntimeEntrypoint,
      files: [
        "dist/channels/weixin/adapter.js",
        daemonRuntimeEntrypoint,
        "dist/daemon/store.js",
      ],
    };
    expect(parseEsmClosureManifest(valid)).toEqual(valid);
    expect(() =>
      parseEsmClosureManifest({
        ...valid,
        version: esmClosureManifestVersion + 1,
      }),
    ).toThrow("version");
    expect(() =>
      parseEsmClosureManifest({
        ...valid,
        entrypoint: "README.md",
        files: ["README.md"],
      }),
    ).toThrow(`entrypoint must be ${daemonRuntimeEntrypoint}`);
    expect(() =>
      parseEsmClosureManifest({
        ...valid,
        files: ["./dist/daemon/main.js"],
      }),
    ).toThrow("non-canonical");
    expect(() =>
      parseEsmClosureManifest({
        ...valid,
        files: [daemonRuntimeEntrypoint, daemonRuntimeEntrypoint],
      }),
    ).toThrow("unique, sorted");
  });

  it("resolves relative imports as canonical package file URLs", async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), "copilot-im-gateway-url-closure-"),
    );
    const mainPath = path.join(root, "dist", "daemon", "main.js");
    try {
      await mkdir(path.dirname(mainPath), { recursive: true });
      await mkdir(path.join(root, "dist", "daemon", "nested"), {
        recursive: true,
      });
      await Promise.all([
        writeFile(
          path.join(root, "dist", "daemon", "store.js"),
          "export {};\n",
          "utf8",
        ),
        writeFile(
          path.join(root, "dist", "daemon", "nested", "decoy.js"),
          "export {};\n",
          "utf8",
        ),
        writeFile(
          path.join(root, "dist", "decoy.js"),
          "export {};\n",
          "utf8",
        ),
        writeFile(path.join(root, "README.md"), "decoy\n", "utf8"),
      ]);

      await writeFile(
        mainPath,
        [
          'import "./store.js";',
          'import "zod";',
          'import "node:fs";',
          "",
        ].join("\n"),
        "utf8",
      );
      await expect(
        collectFilesystemEsmClosure(root, daemonRuntimeEntrypoint),
      ).resolves.toEqual([
        daemonRuntimeEntrypoint,
        "dist/daemon/store.js",
      ]);

      for (const specifier of [
        "./%2e%2e/decoy.js",
        "./nested%2fdecoy.js",
        "./nested%2Fdecoy.js",
        "./nested%5cdecoy.js",
        "./bad%00.js",
      ]) {
        await writeFile(mainPath, `import ${JSON.stringify(specifier)};\n`);
        await expect(
          collectFilesystemEsmClosure(root, daemonRuntimeEntrypoint),
        ).rejects.toThrow("unsafe");
      }

      for (const specifier of [
        "./store.js?raw",
        "./store.js#fragment",
        "#package-import",
      ]) {
        await writeFile(mainPath, `import ${JSON.stringify(specifier)};\n`);
        await expect(
          collectFilesystemEsmClosure(root, daemonRuntimeEntrypoint),
        ).rejects.toThrow("query strings and fragments");
      }

      for (const specifier of [
        "https://example.invalid/decoy.js",
        "data:text/javascript,export default 1",
      ]) {
        await writeFile(mainPath, `import ${JSON.stringify(specifier)};\n`);
        await expect(
          collectFilesystemEsmClosure(root, daemonRuntimeEntrypoint),
        ).rejects.toThrow("file URL");
      }

      for (const specifier of [
        " data:text/javascript,export default 1",
        "\tfile:///outside.js",
        "file:///outside.js\n",
      ]) {
        await writeFile(mainPath, `import ${JSON.stringify(specifier)};\n`);
        await expect(
          collectFilesystemEsmClosure(root, daemonRuntimeEntrypoint),
        ).rejects.toThrow("unsafe");
      }

      await writeFile(mainPath, 'import "../../../README.md";\n');
      await expect(
        collectFilesystemEsmClosure(root, daemonRuntimeEntrypoint),
      ).rejects.toThrow("escapes its package root");
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("rejects a repository without compiled daemon output", async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), "copilot-im-gateway-missing-build-"),
    );
    try {
      await expect(assertBuildOutput(root)).rejects.toThrow(
        "dist/daemon/main.js",
      );
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("rejects missing transitive daemon build modules", async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), "copilot-im-gateway-incomplete-build-"),
    );
    const mainPath = path.join(root, "dist", "daemon", "main.js");
    const storePath = path.join(root, "dist", "daemon", "store.js");
    const channelPath = path.join(
      root,
      "dist",
      "channels",
      "weixin",
      "adapter.js",
    );
    try {
      await mkdir(path.dirname(mainPath), { recursive: true });
      await mkdir(path.dirname(channelPath), { recursive: true });
      await writeFile(
        mainPath,
        'import "./store.js";\nimport "../channels/weixin/adapter.js";\n',
        "utf8",
      );
      await writeFile(storePath, "export {};\n", "utf8");
      await writeFile(channelPath, "export {};\n", "utf8");
      await expect(assertBuildOutput(root)).resolves.toEqual([
        "dist/channels/weixin/adapter.js",
        "dist/daemon/main.js",
        "dist/daemon/store.js",
      ]);

      await rm(storePath);
      await expect(assertBuildOutput(root)).rejects.toThrow(
        "dist/daemon/store.js",
      );
      await writeFile(storePath, "export {};\n", "utf8");
      await rm(channelPath);
      await expect(assertBuildOutput(root)).rejects.toThrow(
        "dist/channels/weixin/adapter.js",
      );
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("creates a deterministic Windows archive with validated contents", async () => {
    const root = await mkdtemp(
      path.join(os.tmpdir(), "copilot-im-gateway-windows-release-"),
    );
    const firstStage = path.join(root, "first");
    const secondStage = path.join(root, "second");
    const incompleteStage = path.join(root, "incomplete");
    const missingStoreStage = path.join(root, "missing-store");
    const missingChannelStage = path.join(root, "missing-channel");
    const readmeEntrypointStage = path.join(root, "readme-entrypoint");
    const packageEntrypointStage = path.join(root, "package-entrypoint");
    const unsupportedVersionStage = path.join(root, "unsupported-version");
    const firstArchive = path.join(root, "first.zip");
    const secondArchive = path.join(root, "second.zip");
    const incompleteArchive = path.join(root, "incomplete.zip");
    const missingStoreArchive = path.join(root, "missing-store.zip");
    const missingChannelArchive = path.join(root, "missing-channel.zip");
    const readmeEntrypointArchive = path.join(
      root,
      "readme-entrypoint.zip",
    );
    const packageEntrypointArchive = path.join(
      root,
      "package-entrypoint.zip",
    );
    const unsupportedVersionArchive = path.join(
      root,
      "unsupported-version.zip",
    );
    try {
      await Promise.all([
        createReleaseFixture(firstStage),
        createReleaseFixture(secondStage),
        createReleaseFixture(
          incompleteStage,
          ".github/extensions/im-gateway/extension-runtime.mjs",
        ),
        createReleaseFixture(missingStoreStage),
        createReleaseFixture(missingChannelStage),
        createReleaseFixture(readmeEntrypointStage),
        createReleaseFixture(packageEntrypointStage),
        createReleaseFixture(unsupportedVersionStage),
      ]);
      await Promise.all([
        rm(path.join(missingStoreStage, "dist", "daemon", "store.js")),
        rm(
          path.join(
            missingChannelStage,
            "dist",
            "channels",
            "weixin",
            "adapter.js",
          ),
        ),
        rewriteClosureManifest(readmeEntrypointStage, {
          entrypoint: "README.md",
          files: ["README.md"],
        }),
        rewriteClosureManifest(packageEntrypointStage, {
          entrypoint: "package.json",
          files: ["package.json"],
        }),
        rewriteClosureManifest(unsupportedVersionStage, {
          version: esmClosureManifestVersion + 1,
        }),
      ]);

      await Promise.all([
        createDeterministicZip(firstStage, firstArchive),
        createDeterministicZip(secondStage, secondArchive),
        createDeterministicZip(missingStoreStage, missingStoreArchive),
        createDeterministicZip(missingChannelStage, missingChannelArchive),
        createDeterministicZip(
          readmeEntrypointStage,
          readmeEntrypointArchive,
        ),
        createDeterministicZip(
          packageEntrypointStage,
          packageEntrypointArchive,
        ),
        createDeterministicZip(
          unsupportedVersionStage,
          unsupportedVersionArchive,
        ),
      ]);
      const [
        firstChecksum,
        secondChecksum,
        missingStoreChecksum,
        missingChannelChecksum,
        readmeEntrypointChecksum,
        packageEntrypointChecksum,
        unsupportedVersionChecksum,
      ] = await Promise.all([
        writeChecksum(firstArchive),
        writeChecksum(secondArchive),
        writeChecksum(missingStoreArchive),
        writeChecksum(missingChannelArchive),
        writeChecksum(readmeEntrypointArchive),
        writeChecksum(packageEntrypointArchive),
        writeChecksum(unsupportedVersionArchive),
      ]);

      await validateReleaseArchive(firstArchive, firstChecksum.checksumPath);
      await validateReleaseArchive(secondArchive, secondChecksum.checksumPath);
      expect(firstChecksum.digest).toBe(secondChecksum.digest);
      expect(
        createHash("sha256")
          .update(await readFile(firstArchive))
          .digest("hex"),
      ).toBe(firstChecksum.digest);

      await createDeterministicZip(incompleteStage, incompleteArchive);
      const incompleteChecksum = await writeChecksum(incompleteArchive);
      await expect(
        validateReleaseArchive(
          incompleteArchive,
          incompleteChecksum.checksumPath,
        ),
      ).rejects.toThrow("extension-runtime.mjs");
      await expect(
        validateReleaseArchive(
          missingStoreArchive,
          missingStoreChecksum.checksumPath,
        ),
      ).rejects.toThrow("dist/daemon/store.js");
      await expect(
        validateReleaseArchive(
          missingChannelArchive,
          missingChannelChecksum.checksumPath,
        ),
      ).rejects.toThrow("dist/channels/weixin/adapter.js");
      await expect(
        validateReleaseArchive(
          readmeEntrypointArchive,
          readmeEntrypointChecksum.checksumPath,
        ),
      ).rejects.toThrow(`entrypoint must be ${daemonRuntimeEntrypoint}`);
      await expect(
        validateReleaseArchive(
          packageEntrypointArchive,
          packageEntrypointChecksum.checksumPath,
        ),
      ).rejects.toThrow(`entrypoint must be ${daemonRuntimeEntrypoint}`);
      await expect(
        validateReleaseArchive(
          unsupportedVersionArchive,
          unsupportedVersionChecksum.checksumPath,
        ),
      ).rejects.toThrow(
        `manifest version must be ${esmClosureManifestVersion}`,
      );

      await writeFile(firstChecksum.checksumPath, "invalid  first.zip\n", "utf8");
      await expect(
        validateReleaseArchive(firstArchive, firstChecksum.checksumPath),
      ).rejects.toThrow("checksum");
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });

  it("pins and wires the self-contained Windows installer", async () => {
    const root = path.resolve(import.meta.dirname, "..");
    const buildScript = await readFile(
      path.join(root, "scripts", "installer", "build-windows-installer.ps1"),
      "utf8",
    );
    const installer = await readFile(
      path.join(root, "scripts", "installer", "windows-installer.iss"),
      "utf8",
    );
    const releaseWorkflow = await readFile(
      path.join(root, ".github", "workflows", "release.yml"),
      "utf8",
    );
    const installScript = await readFile(
      path.join(root, "scripts", "release", "install.ps1"),
      "utf8",
    );
    const stopDaemonScript = await readFile(
      path.join(root, "scripts", "release", "stop-daemon.ps1"),
      "utf8",
    );
    const credentialKeyScript = await readFile(
      path.join(root, "scripts", "release", "credential-key.ps1"),
      "utf8",
    );
    const installerSmoke = await readFile(
      path.join(root, "scripts", "installer", "smoke-windows-installer.ps1"),
      "utf8",
    );

    expect(buildScript).toContain('$nodeVersion = "24.11.1"');
    expect(buildScript).toContain(
      '$nodeArchiveSha256 = "5355ae6d7c49eddcfde7d34ac3486820600a831bf81dc3bdca5c8db6a9bb0e76"',
    );
    expect(buildScript).toContain("npm-cli.js");
    expect(buildScript).toContain("esm-closure.mjs");
    expect(buildScript).toContain("daemon-runtime-closure.json");
    expect(buildScript).toContain("credential-key.ps1");
    expect(installer).toContain("PrivilegesRequired=lowest");
    expect(installer).toContain("ArchitecturesAllowed=x64compatible");
    expect(installer).toContain("Copilot-IM-Gateway-Setup-v{#AppVersion}-x64");
    expect(installer).not.toContain("runascurrentuser");
    expect(installer).toContain("PrepareToInstall");
    expect(installer).toContain("credential-key.ps1");
    expect(installer).toContain("ExtractTemporaryFile('stop-daemon.ps1')");
    expect(installer).toContain(
      "GatewayPort := StrToIntDef(PortText, -1);",
    );
    expect(installer).toContain(
      "(GatewayPort < 0) or (GatewayPort > 65535)",
    );
    expect(installer).not.toContain("TryStrToInt");
    expect(releaseWorkflow).toContain("npm run release:installer:smoke");
    expect(releaseWorkflow).toContain("release/*.exe");
    expect(installerSmoke).not.toContain("Get-FileHash");
    expect(installerSmoke).toContain(
      "$stream = [System.IO.File]::OpenRead($Path)",
    );
    expect(installerSmoke).toContain(
      "$hasher = [System.Security.Cryptography.SHA256]::Create()",
    );
    expect(installerSmoke).toContain("$hash = $hasher.ComputeHash($stream)");
    expect(installerSmoke).toContain(
      '[BitConverter]::ToString($hash).Replace("-", "").ToLowerInvariant()',
    );
    expect(installerSmoke).toContain("$hasher.Dispose()");
    expect(installerSmoke).toContain("$stream.Dispose()");
    expect(installerSmoke).toContain(
      "$keyHashBeforeUpgrade = Get-Sha256Hex -Path $keyPath",
    );
    expect(installerSmoke).toContain(
      "if ((Get-Sha256Hex -Path $keyPath) -ne $keyHashBeforeUpgrade)",
    );
    expect(installScript).toContain(
      "$nodeVersion.Major -eq 22 -and $nodeVersion.Minor -ge 13",
    );
    expect(installScript).toContain(
      "Node.js 22.13+ (excluding 23.x) or 24+ is required",
    );
    expect(installScript).not.toContain("22.12");
    expect(installScript.indexOf("stop-daemon.ps1")).toBeLessThan(
      installScript.indexOf(
        "Remove-Item -LiteralPath $installDirectory -Recurse -Force",
      ),
    );
    expect(stopDaemonScript).toContain("Get-CimInstance Win32_Process");
    expect(stopDaemonScript).toContain("MSFT_NetTCPConnection");
    expect(stopDaemonScript).toContain("GetFinalPathNameByHandle");
    expect(stopDaemonScript).toContain("OwningProcess");
    expect(stopDaemonScript).toContain("CreationMarker");
    expect(stopDaemonScript).toContain("CommandLineToArgvW");
    expect(stopDaemonScript).toContain("Test-GatewayProcess");
    expect(stopDaemonScript).toContain("Get-ValidatedGatewayListenerOwner");
    expect(stopDaemonScript).toContain("Test-GatewayProcessRecord");
    expect(stopDaemonScript).toContain("/v2/admin/shutdown");
    expect(stopDaemonScript).toContain("/v2/admin/identity");
    expect(stopDaemonScript).toContain("Get-HmacSha256Hex");
    expect(stopDaemonScript).toContain("clientNonce");
    expect(stopDaemonScript).toContain("responseProof");
    expect(stopDaemonScript).toContain("[Net.Sockets.TcpClient]::new()");
    expect(stopDaemonScript).toContain("Connection: close");
    expect(stopDaemonScript).toContain(
      "[Text.Encoding]::UTF8.GetBytes($requestBody)",
    );
    expect(stopDaemonScript).toContain(
      'ContentType "application/json; charset=utf-8"',
    );
    expect(stopDaemonScript).toContain(
      "Exit the old Copilot IM Gateway and retry.",
    );
    expect(
      [
        buildScript,
        installScript,
        installer,
        stopDaemonScript,
        credentialKeyScript,
      ].join("\n"),
    ).not.toContain("Stop-Process");
    expect(stopDaemonScript).not.toContain("Wait-Process");
    expect(stopDaemonScript).not.toContain("FallbackLeaseWaitSeconds");
    expect(stopDaemonScript).not.toContain("Get-RevalidatedGatewayProcess");
    expect(stopDaemonScript).not.toContain("$commandLine.IndexOf");
    expect(stopDaemonScript).toContain(
      "[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)",
    );
    expect(installScript).toContain(
      "Upgrade aborted before replacing installed files.",
    );
    expect(installer).toContain(
      "Exit the old Copilot IM Gateway and retry.",
    );
    expect(installer).toContain("{param:GATEWAYDATADIR|}");
    expect(installer).toContain("{param:GATEWAYTOKENFILE|}");
    expect(installer).toContain("{param:GATEWAYPORT|}");
    expect(installerSmoke).toContain("verify");
    expect(installerSmoke).toContain("daemon-runtime-closure.json");
    expect(installerSmoke).toContain(
      "Upgrade did not gracefully shut down the old daemon process.",
    );
    expect(installerSmoke).toContain(
      "Upgrade did not wait for loopback port release.",
    );
    expect(credentialKeyScript).toContain("SetAccessRuleProtection($true, $false)");
    expect(credentialKeyScript).toContain(
      "[GatewayDurableMove]::MoveFileEx",
    );
    expect(credentialKeyScript).toContain("$moveFileWriteThrough = 8");
    expect(credentialKeyScript).toContain(
      "[Security.Principal.WindowsIdentity]::GetCurrent().User",
    );
    expect(credentialKeyScript).toContain("$rules.Count -ne 1");
    expect(credentialKeyScript).toContain("[IO.FileMode]::CreateNew");
    expect(credentialKeyScript).toContain("$stream.Flush($true)");
    expect(credentialKeyScript).not.toContain("icacls");
    expect(installerSmoke).toContain(
      "Upgrade did not reuse the existing credential master key.",
    );
    expect(installerSmoke).toContain(
      "Uninstaller silently removed the credential master key.",
    );
  });

  it.skipIf(process.platform !== "win32")(
    "recovers every durable Windows key-swap stage before requiring the canonical key",
    async () => {
      const root = await mkdtemp(
        path.join(os.tmpdir(), "copilot-im-gateway-key-recovery-"),
      );
      const helper = path.resolve(
        import.meta.dirname,
        "..",
        "scripts",
        "release",
        "credential-key.ps1",
      );
      const fakeNode = path.join(root, "classify-next.cmd");
      const fakeCurrentNode = path.join(root, "classify-current.cmd");
      await writeFile(fakeNode, "@exit /b 21\r\n", "utf8");
      await writeFile(fakeCurrentNode, "@exit /b 20\r\n", "utf8");
      const invokeHelper = (
        dataDirectory: string,
        argumentsValue: string[] = [],
        environment: NodeJS.ProcessEnv = {},
      ): SpawnSyncReturns<string> =>
        spawnSync(
          "powershell.exe",
          [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            helper,
            "-DataDirectory",
            dataDirectory,
            ...argumentsValue,
          ],
          {
            encoding: "utf8",
            env: { ...process.env, ...environment },
            timeout: slowPowerShellTimeout,
            windowsHide: true,
          },
        );
      try {
        for (const stage of [
          "before-retirement-move",
          "between-renames",
          "after-canonical-rename",
          "wiping-intact-marker",
          "wiping-partial-marker",
          "after-marker-delete",
        ]) {
          const dataDirectory = path.join(root, stage);
          let result = invokeHelper(dataDirectory);
          expectSpawnCompleted(result);
          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
          const currentPath = path.join(
            dataDirectory,
            "credential-master-key",
          );
          const nextPath = `${currentPath}.next`;
          const previousPath = `${currentPath}.previous`;
          const rotationPath = `${currentPath}.rotation`;
          const journalFixturePath = `${currentPath}.journal-fixture`;
          const oldKey = await readFile(currentPath);
          await rename(currentPath, journalFixturePath);
          result = invokeHelper(dataDirectory);
          expectSpawnCompleted(result);
          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
          await writeFile(currentPath, oldKey);
          result = invokeHelper(dataDirectory, ["-ProvisionNext"]);
          expectSpawnCompleted(result);
          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
          const nextKey = await readFile(nextPath);
          const currentKeyId = createHash("sha256")
            .update(oldKey)
            .digest("hex");
          const retirementMarker = `credential-master-key.retire-${currentKeyId}`;
          const retirementPath = path.join(
            dataDirectory,
            retirementMarker,
          );
          const journal = {
            version: 2,
            currentKeyId,
            nextKeyId: createHash("sha256").update(nextKey).digest("hex"),
            retirementMarker,
            retirementKeyId: currentKeyId,
            retirementState: stage.startsWith("wiping-") ||
              stage === "after-marker-delete"
              ? "wiping"
              : "prepared",
          };
          await rename(journalFixturePath, rotationPath);
          await writeFile(
            rotationPath,
            `${JSON.stringify(journal)}\n`,
            "utf8",
          );
          if (stage === "between-renames") {
            await rename(currentPath, retirementPath);
          } else if (
            stage === "after-canonical-rename" ||
            stage === "wiping-intact-marker" ||
            stage === "wiping-partial-marker"
          ) {
            await rename(currentPath, retirementPath);
            await rename(nextPath, currentPath);
            if (stage === "wiping-partial-marker") {
              await writeFile(
                retirementPath,
                Buffer.concat([
                  Buffer.alloc(11),
                  oldKey.subarray(11),
                ]),
              );
            }
          } else if (stage === "after-marker-delete") {
            await rename(currentPath, retirementPath);
            await rename(nextPath, currentPath);
            await rm(retirementPath);
          }

          const recoveryArguments = [
            "-RecoverRotation",
            "-NodePath",
            fakeNode,
            "-MaintenanceEntryPoint",
            "fixture",
          ];
          result = invokeHelper(
            dataDirectory,
            recoveryArguments,
            stage === "wiping-intact-marker"
              ? {
                  NODE_ENV: "test",
                  COPILOT_IM_GATEWAY_TEST_TORN_RETIREMENT_WIPE: "1",
                }
              : stage === "wiping-partial-marker"
              ? {
                  NODE_ENV: "test",
                  COPILOT_IM_GATEWAY_TEST_DEFER_RETIREMENT_CLEANUP: "1",
                }
              : {},
          );
          expectSpawnCompleted(result);
          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
          if (
            stage === "wiping-intact-marker" ||
            stage === "wiping-partial-marker"
          ) {
            await expect(readFile(currentPath)).resolves.toEqual(nextKey);
            await expect(readFile(retirementPath)).resolves.toHaveLength(32);
            await expect(
              readFile(rotationPath, "utf8"),
            ).resolves.toContain('"retirementState":"wiping"');
            result = invokeHelper(dataDirectory, recoveryArguments);
            expectSpawnCompleted(result);
            expect(
              result.status,
              `${result.stdout}\n${result.stderr}`,
            ).toBe(0);
          }
          await expect(readFile(currentPath)).resolves.toEqual(nextKey);
          for (const transientPath of [
            nextPath,
            previousPath,
            retirementPath,
            rotationPath,
          ]) {
            try {
              await readFile(transientPath);
              throw new Error(
                `Recovery left ${stage} artifact ${transientPath}.`,
              );
            } catch (error) {
              if (
                error instanceof Error &&
                "code" in error &&
                error.code === "ENOENT"
              ) {
                continue;
              }
              throw error;
            }
          }
          await expect(
            readFile(`${currentPath}.rotation-completed`, "utf8"),
          ).resolves.toContain(journal.nextKeyId);
          result = invokeHelper(dataDirectory);
          expectSpawnCompleted(result);
          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
        }
        for (const stage of [
          "legacy-marker-before-canonical",
          "legacy-marker-after-canonical",
          "legacy-partial-previous",
          "legacy-partial-marker",
        ]) {
          const dataDirectory = path.join(root, stage);
          let result = invokeHelper(dataDirectory);
          expectSpawnCompleted(result);
          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
          const currentPath = path.join(
            dataDirectory,
            "credential-master-key",
          );
          const nextPath = `${currentPath}.next`;
          const previousPath = `${currentPath}.previous`;
          const rotationPath = `${currentPath}.rotation`;
          const fixturePath = `${currentPath}.journal-fixture`;
          const oldKey = await readFile(currentPath);
          await rename(currentPath, fixturePath);
          result = invokeHelper(dataDirectory);
          expectSpawnCompleted(result);
          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
          await writeFile(currentPath, oldKey);
          result = invokeHelper(dataDirectory, ["-ProvisionNext"]);
          expectSpawnCompleted(result);
          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
          const nextKey = await readFile(nextPath);
          const oldKeyId = createHash("sha256").update(oldKey).digest("hex");
          const markerPath = path.join(
            dataDirectory,
            `credential-master-key.retire-${oldKeyId}`,
          );
          await rename(fixturePath, rotationPath);
          await writeFile(
            rotationPath,
            `${JSON.stringify({
              version: 1,
              currentKeyId: oldKeyId,
              nextKeyId: createHash("sha256").update(nextKey).digest("hex"),
            })}\n`,
            "utf8",
          );
          await rename(currentPath, markerPath);
          if (stage === "legacy-marker-after-canonical") {
            await rename(nextPath, currentPath);
          } else if (stage === "legacy-partial-previous") {
            await rename(markerPath, previousPath);
            await rename(nextPath, currentPath);
            await writeFile(
              previousPath,
              Buffer.concat([
                Buffer.alloc(13),
                oldKey.subarray(13),
              ]),
            );
          } else if (stage === "legacy-partial-marker") {
            await rename(nextPath, currentPath);
            await writeFile(
              markerPath,
              Buffer.concat([
                Buffer.alloc(17),
                oldKey.subarray(17),
              ]),
            );
          }

          result = invokeHelper(dataDirectory, [
            "-RecoverRotation",
            "-NodePath",
            fakeNode,
            "-MaintenanceEntryPoint",
            "fixture",
          ]);
          expectSpawnCompleted(result);
          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
          await expect(readFile(currentPath)).resolves.toEqual(nextKey);
          for (const transientPath of [
            nextPath,
            previousPath,
            markerPath,
            rotationPath,
          ]) {
            await expect(readFile(transientPath)).rejects.toMatchObject({
              code: "ENOENT",
            });
          }
        }
        for (const version of [1, 2]) {
          const dataDirectory = path.join(
            root,
            `rollback-abort-marker-v${version}`,
          );
          let result = invokeHelper(dataDirectory);
          expectSpawnCompleted(result);
          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
          const currentPath = path.join(
            dataDirectory,
            "credential-master-key",
          );
          const nextPath = `${currentPath}.next`;
          const rotationPath = `${currentPath}.rotation`;
          const fixturePath = `${currentPath}.journal-fixture`;
          const currentKey = await readFile(currentPath);
          await rename(currentPath, fixturePath);
          result = invokeHelper(dataDirectory);
          expectSpawnCompleted(result);
          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
          await writeFile(currentPath, currentKey);
          result = invokeHelper(dataDirectory, ["-ProvisionNext"]);
          expectSpawnCompleted(result);
          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
          const nextKey = await readFile(nextPath);
          const currentKeyId = createHash("sha256")
            .update(currentKey)
            .digest("hex");
          const nextKeyId = createHash("sha256")
            .update(nextKey)
            .digest("hex");
          const abortPath = path.join(
            dataDirectory,
            `credential-master-key.abort-${nextKeyId}`,
          );
          const journal = version === 1
            ? {
                version: 1,
                currentKeyId,
                nextKeyId,
              }
            : {
                version: 2,
                currentKeyId,
                nextKeyId,
                retirementMarker:
                  `credential-master-key.retire-${currentKeyId}`,
                retirementKeyId: currentKeyId,
                retirementState: "prepared",
              };
          await rename(fixturePath, rotationPath);
          await writeFile(
            rotationPath,
            `${JSON.stringify(journal)}\n`,
            "utf8",
          );
          if (version === 1) {
            await writeFile(
              nextPath,
              Buffer.concat([
                Buffer.alloc(9),
                nextKey.subarray(9),
              ]),
            );
          }
          await rename(nextPath, abortPath);

          result = invokeHelper(dataDirectory, [
            "-RecoverRotation",
            "-NodePath",
            fakeCurrentNode,
            "-MaintenanceEntryPoint",
            "fixture",
          ]);
          expectSpawnCompleted(result);
          expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
          await expect(readFile(currentPath)).resolves.toEqual(currentKey);
          for (const transientPath of [
            nextPath,
            abortPath,
            rotationPath,
          ]) {
            await expect(readFile(transientPath)).rejects.toMatchObject({
              code: "ENOENT",
            });
          }
        }
        const invalidDirectory = path.join(root, "invalid-journal");
        let invalidResult = invokeHelper(invalidDirectory);
        expectSpawnCompleted(invalidResult);
        expect(
          invalidResult.status,
          `${invalidResult.stdout}\n${invalidResult.stderr}`,
        ).toBe(0);
        const invalidKeyPath = path.join(
          invalidDirectory,
          "credential-master-key",
        );
        const invalidRotationPath = `${invalidKeyPath}.rotation`;
        await rename(invalidKeyPath, invalidRotationPath);
        await writeFile(invalidRotationPath, '{"version":1}\n', "utf8");
        invalidResult = invokeHelper(invalidDirectory, [
          "-RecoverRotation",
          "-NodePath",
          fakeNode,
          "-MaintenanceEntryPoint",
          "fixture",
        ]);
        expectSpawnCompleted(invalidResult);
        expect(
          invalidResult.status,
          `${invalidResult.stdout}\n${invalidResult.stderr}`,
        ).not.toBe(0);
        await expect(readFile(invalidKeyPath)).rejects.toMatchObject({
          code: "ENOENT",
        });
        await expect(
          readFile(invalidRotationPath, "utf8"),
        ).resolves.toBe('{"version":1}\n');

        const malformedDirectory = path.join(root, "malformed-next-path");
        let malformedResult = invokeHelper(malformedDirectory);
        expectSpawnCompleted(malformedResult);
        expect(
          malformedResult.status,
          `${malformedResult.stdout}\n${malformedResult.stderr}`,
        ).toBe(0);
        const malformedKeyPath = path.join(
          malformedDirectory,
          "credential-master-key",
        );
        const malformedNextPath = `${malformedKeyPath}.next`;
        const malformedRotationPath = `${malformedKeyPath}.rotation`;
        const malformedFixturePath = `${malformedKeyPath}.journal-fixture`;
        const malformedOldKey = await readFile(malformedKeyPath);
        await rename(malformedKeyPath, malformedFixturePath);
        malformedResult = invokeHelper(malformedDirectory);
        expectSpawnCompleted(malformedResult);
        expect(
          malformedResult.status,
          `${malformedResult.stdout}\n${malformedResult.stderr}`,
        ).toBe(0);
        await writeFile(malformedKeyPath, malformedOldKey);
        malformedResult = invokeHelper(malformedDirectory, ["-ProvisionNext"]);
        expectSpawnCompleted(malformedResult);
        expect(
          malformedResult.status,
          `${malformedResult.stdout}\n${malformedResult.stderr}`,
        ).toBe(0);
        const malformedNextKey = await readFile(malformedNextPath);
        await rename(malformedFixturePath, malformedRotationPath);
        await writeFile(
          malformedRotationPath,
          `${JSON.stringify({
            version: 2,
            currentKeyId: createHash("sha256").update(malformedOldKey).digest("hex"),
            nextKeyId: createHash("sha256")
              .update(malformedNextKey)
              .digest("hex"),
            retirementMarker: `credential-master-key.retire-${createHash("sha256")
              .update(malformedOldKey)
              .digest("hex")}`,
            retirementKeyId: createHash("sha256")
              .update(malformedOldKey)
              .digest("hex"),
            retirementState: "prepared",
          })}\n`,
          "utf8",
        );
        await rm(malformedNextPath);
        await mkdir(malformedNextPath);
        malformedResult = invokeHelper(malformedDirectory, [
          "-RecoverRotation",
          "-NodePath",
          fakeNode,
          "-MaintenanceEntryPoint",
          "fixture",
        ]);
        expectSpawnCompleted(malformedResult);
        expect(
          malformedResult.status,
          `${malformedResult.stdout}\n${malformedResult.stderr}`,
        ).not.toBe(0);
        await expect(readFile(malformedKeyPath)).resolves.toEqual(
          malformedOldKey,
        );
        await expect(
          readFile(malformedRotationPath, "utf8"),
        ).resolves.toContain("nextKeyId");

        const forgedDirectory = path.join(root, "forged-retirement-marker");
        let forgedResult = invokeHelper(forgedDirectory);
        expectSpawnCompleted(forgedResult);
        expect(
          forgedResult.status,
          `${forgedResult.stdout}\n${forgedResult.stderr}`,
        ).toBe(0);
        const forgedKeyPath = path.join(
          forgedDirectory,
          "credential-master-key",
        );
        const forgedNextPath = `${forgedKeyPath}.next`;
        const forgedRotationPath = `${forgedKeyPath}.rotation`;
        const forgedFixturePath = `${forgedKeyPath}.journal-fixture`;
        const forgedOldKey = await readFile(forgedKeyPath);
        await rename(forgedKeyPath, forgedFixturePath);
        forgedResult = invokeHelper(forgedDirectory);
        expectSpawnCompleted(forgedResult);
        expect(
          forgedResult.status,
          `${forgedResult.stdout}\n${forgedResult.stderr}`,
        ).toBe(0);
        await writeFile(forgedKeyPath, forgedOldKey);
        forgedResult = invokeHelper(forgedDirectory, ["-ProvisionNext"]);
        expectSpawnCompleted(forgedResult);
        expect(
          forgedResult.status,
          `${forgedResult.stdout}\n${forgedResult.stderr}`,
        ).toBe(0);
        const forgedNextKey = await readFile(forgedNextPath);
        const forgedOldKeyId = createHash("sha256")
          .update(forgedOldKey)
          .digest("hex");
        const forgedMarkerName =
          `credential-master-key.retire-${forgedOldKeyId}`;
        const forgedMarkerPath = path.join(
          forgedDirectory,
          forgedMarkerName,
        );
        await rename(forgedFixturePath, forgedRotationPath);
        await writeFile(
          forgedRotationPath,
          `${JSON.stringify({
            version: 2,
            currentKeyId: forgedOldKeyId,
            nextKeyId: createHash("sha256")
              .update(forgedNextKey)
              .digest("hex"),
            retirementMarker: forgedMarkerName,
            retirementKeyId: forgedOldKeyId,
            retirementState: "prepared",
          })}\n`,
          "utf8",
        );
        await rename(forgedKeyPath, forgedMarkerPath);
        await writeFile(forgedMarkerPath, Buffer.alloc(32, 0x5a));
        await rename(forgedNextPath, forgedKeyPath);
        forgedResult = invokeHelper(forgedDirectory, [
          "-RecoverRotation",
          "-NodePath",
          fakeNode,
          "-MaintenanceEntryPoint",
          "fixture",
        ]);
        expectSpawnCompleted(forgedResult);
        expect(
          forgedResult.status,
          `${forgedResult.stdout}\n${forgedResult.stderr}`,
        ).not.toBe(0);
        await expect(readFile(forgedKeyPath)).resolves.toEqual(forgedNextKey);
        await expect(readFile(forgedMarkerPath)).resolves.toEqual(
          Buffer.alloc(32, 0x5a),
        );
        await expect(
          readFile(forgedRotationPath, "utf8"),
        ).resolves.toContain(forgedOldKeyId);

        const hardLinkDirectory = path.join(root, "hard-link-marker");
        let hardLinkResult = invokeHelper(hardLinkDirectory);
        expectSpawnCompleted(hardLinkResult);
        expect(
          hardLinkResult.status,
          `${hardLinkResult.stdout}\n${hardLinkResult.stderr}`,
        ).toBe(0);
        const hardLinkKeyPath = path.join(
          hardLinkDirectory,
          "credential-master-key",
        );
        const hardLinkNextPath = `${hardLinkKeyPath}.next`;
        const hardLinkRotationPath = `${hardLinkKeyPath}.rotation`;
        const hardLinkFixturePath = `${hardLinkKeyPath}.journal-fixture`;
        await rename(hardLinkKeyPath, hardLinkFixturePath);
        hardLinkResult = invokeHelper(hardLinkDirectory);
        expectSpawnCompleted(hardLinkResult);
        expect(
          hardLinkResult.status,
          `${hardLinkResult.stdout}\n${hardLinkResult.stderr}`,
        ).toBe(0);
        hardLinkResult = invokeHelper(hardLinkDirectory, ["-ProvisionNext"]);
        expectSpawnCompleted(hardLinkResult);
        expect(
          hardLinkResult.status,
          `${hardLinkResult.stdout}\n${hardLinkResult.stderr}`,
        ).toBe(0);
        const hardLinkOldKey = await readFile(hardLinkKeyPath);
        const hardLinkNextKey = await readFile(hardLinkNextPath);
        const hardLinkOldKeyId = createHash("sha256")
          .update(hardLinkOldKey)
          .digest("hex");
        const hardLinkMarkerName =
          `credential-master-key.retire-${hardLinkOldKeyId}`;
        const hardLinkMarkerPath = path.join(
          hardLinkDirectory,
          hardLinkMarkerName,
        );
        await rename(hardLinkFixturePath, hardLinkRotationPath);
        await writeFile(
          hardLinkRotationPath,
          `${JSON.stringify({
            version: 2,
            currentKeyId: hardLinkOldKeyId,
            nextKeyId: createHash("sha256")
              .update(hardLinkNextKey)
              .digest("hex"),
            retirementMarker: hardLinkMarkerName,
            retirementKeyId: hardLinkOldKeyId,
            retirementState: "wiping",
          })}\n`,
          "utf8",
        );
        await rm(hardLinkKeyPath);
        await rename(hardLinkNextPath, hardLinkKeyPath);
        await link(hardLinkKeyPath, hardLinkMarkerPath);
        hardLinkResult = invokeHelper(hardLinkDirectory, [
          "-RecoverRotation",
          "-NodePath",
          fakeNode,
          "-MaintenanceEntryPoint",
          "fixture",
        ]);
        expectSpawnCompleted(hardLinkResult);
        expect(
          hardLinkResult.status,
          `${hardLinkResult.stdout}\n${hardLinkResult.stderr}`,
        ).not.toBe(0);
        await expect(readFile(hardLinkKeyPath)).resolves.toEqual(
          hardLinkNextKey,
        );
        await expect(readFile(hardLinkMarkerPath)).resolves.toEqual(
          hardLinkNextKey,
        );
      } finally {
        await rm(root, { force: true, recursive: true });
      }
    },
    180_000,
  );

  it.skipIf(process.platform !== "win32")(
    "does not disclose the token or trust shutdown responses from an unknown listener",
    async () => {
      const root = await mkdtemp(
        path.join(os.tmpdir(), "copilot-im-gateway-unknown-stop-"),
      );
      const installDirectory = path.join(root, "install");
      const dataDirectory = path.join(root, "data");
      const tokenFile = path.join(dataDirectory, "auth-token");
      const listenerScript = path.join(root, "unknown-listener.cjs");
      const readyFile = path.join(root, "ready");
      const requestFile = path.join(root, "request-received");
      let listener: ChildProcess | undefined;
      try {
        await Promise.all([
          mkdir(installDirectory, { recursive: true }),
          mkdir(dataDirectory, { recursive: true }),
        ]);
        await Promise.all([
          writeFile(
            listenerScript,
            [
              'const http = require("node:http");',
              'const fs = require("node:fs");',
              "const port = Number(process.argv[2]);",
              "const ready = process.argv[3];",
              "const received = process.argv[4];",
              "const server = http.createServer((_request, response) => {",
              '  fs.writeFileSync(received, "received");',
              '  response.writeHead(202, { "Content-Type": "application/json" });',
              '  response.end(\'{"accepted":true}\');',
              "});",
              'server.listen(port, "127.0.0.1", () => {',
              '  fs.writeFileSync(ready, "ready");',
              "});",
              "",
            ].join("\n"),
            "utf8",
          ),
          writeFile(tokenFile, `${"a".repeat(64)}\n`, "utf8"),
        ]);
        const port = await availablePort();
        listener = spawn(
          process.execPath,
          [listenerScript, String(port), readyFile, requestFile],
          { stdio: "ignore", windowsHide: true },
        );
        await waitForFile(readyFile);

        const stopScript = path.resolve(
          import.meta.dirname,
          "..",
          "scripts",
          "release",
          "stop-daemon.ps1",
        );
        const blocked = spawnSync(
          "powershell.exe",
          [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            stopScript,
            "-InstallDirectory",
            installDirectory,
            "-DataDirectory",
            dataDirectory,
            "-TokenFile",
            tokenFile,
            "-Port",
            String(port),
            "-TimeoutSeconds",
            "2",
          ],
          {
            encoding: "utf8",
            timeout: slowPowerShellTimeout,
            windowsHide: true,
          },
        );
        expectSpawnCompleted(blocked);
        expect(
          blocked.status,
          `${blocked.stdout}\n${blocked.stderr}`,
        ).not.toBe(0);
        expect(
          `${blocked.stdout}\n${blocked.stderr}`.replace(/\s+/gu, " "),
        ).toContain(
          "Exit the old Copilot IM Gateway",
        );
        expect(listener.exitCode).toBeNull();
        await expect(readFile(requestFile, "utf8")).rejects.toMatchObject({
          code: "ENOENT",
        });
      } finally {
        if (listener !== undefined) {
          await stopTestProcess(listener);
        }
        await rm(root, { force: true, recursive: true });
      }
    },
    30_000,
  );

  it.skipIf(process.platform !== "win32")(
    "leaves a legacy daemon and its data untouched until the user exits it",
    async () => {
      const root = await mkdtemp(
        path.join(os.tmpdir(), "copilot-im-gateway-legacy-stop-"),
      );
      const installDirectory = path.join(root, "install");
      const dataDirectory = path.join(root, "data");
      const entrypoint = path.join(
        installDirectory,
        "app",
        "dist",
        "daemon",
        "main.js",
      );
      const tokenFile = path.join(dataDirectory, "auth-token");
      const sentinelFile = path.join(dataDirectory, "gateway.sqlite");
      const readyFile = path.join(root, "ready");
      const sentinel = Buffer.from([
        0x53,
        0x51,
        0x4c,
        0x69,
        0x74,
        0x65,
        0x00,
        0xff,
      ]);
      let legacy: ChildProcess | undefined;
      try {
        await Promise.all([
          mkdir(path.dirname(entrypoint), { recursive: true }),
          mkdir(dataDirectory, { recursive: true }),
        ]);
        await Promise.all([
          writeFile(
            entrypoint,
            [
              'const http = require("node:http");',
              'const fs = require("node:fs");',
              "const port = Number(process.argv[2]);",
              "const ready = process.argv[3];",
              "const server = http.createServer((_request, response) => {",
              "  response.writeHead(404);",
              '  response.end("legacy");',
              "});",
              'server.listen(port, "127.0.0.1", () => {',
              '  fs.writeFileSync(ready, "ready");',
              "});",
              "",
            ].join("\n"),
            "utf8",
          ),
          writeFile(tokenFile, `${"a".repeat(64)}\n`, "utf8"),
          writeFile(sentinelFile, sentinel),
        ]);
        const port = await availablePort();
        legacy = spawn(
          process.execPath,
          [entrypoint, String(port), readyFile],
          {
            stdio: "ignore",
            windowsHide: true,
          },
        );
        await waitForFile(readyFile);

        const stopScript = path.resolve(
          import.meta.dirname,
          "..",
          "scripts",
          "release",
          "stop-daemon.ps1",
        );
        const stopArguments = [
          "-NoProfile",
          "-NonInteractive",
          "-ExecutionPolicy",
          "Bypass",
          "-File",
          stopScript,
          "-InstallDirectory",
          installDirectory,
          "-DataDirectory",
          dataDirectory,
          "-TokenFile",
          tokenFile,
          "-Port",
          String(port),
          "-TimeoutSeconds",
          "2",
        ];
        const blocked = spawnSync("powershell.exe", stopArguments, {
          encoding: "utf8",
          timeout: slowPowerShellTimeout,
          windowsHide: true,
        });
        expectSpawnCompleted(blocked);
        expect(
          blocked.status,
          `${blocked.stdout}\n${blocked.stderr}`,
        ).not.toBe(0);
        expect(
          `${blocked.stdout}\n${blocked.stderr}`.replace(/\s+/gu, " "),
        ).toContain(
          "Exit the old Copilot IM Gateway",
        );
        expect(legacy.exitCode).toBeNull();
        expect(await readFile(sentinelFile)).toEqual(sentinel);

        await stopTestProcess(legacy);
        const unblocked = spawnSync("powershell.exe", stopArguments, {
          encoding: "utf8",
          timeout: slowPowerShellTimeout,
          windowsHide: true,
        });
        expectSpawnCompleted(unblocked);
        expect(
          unblocked.status,
          `${unblocked.stdout}\n${unblocked.stderr}`,
        ).toBe(0);

        await writeFile(
          path.join(installDirectory, "upgrade-complete"),
          "upgraded\n",
          "utf8",
        );
        const restarted = createServer();
        await new Promise<void>((resolve, reject) => {
          restarted.once("error", reject);
          restarted.listen(port, "127.0.0.1", resolve);
        });
        await new Promise<void>((resolve, reject) => {
          restarted.close((error) => {
            if (error) {
              reject(error);
            } else {
              resolve();
            }
          });
        });
        expect(await readFile(sentinelFile)).toEqual(sentinel);
      } finally {
        if (legacy !== undefined) {
          await stopTestProcess(legacy);
        }
        await rm(root, { force: true, recursive: true });
      }
    },
    30_000,
  );

  it.skipIf(process.platform !== "win32")(
    "rejects bearer tokens that could inject an HTTP header",
    async () => {
      const root = await mkdtemp(
        path.join(os.tmpdir(), "copilot-im-gateway-token-format-"),
      );
      try {
        const installDirectory = path.join(root, "install");
        const dataDirectory = path.join(root, "data");
        const tokenFile = path.join(dataDirectory, "auth-token");
        const identityMarker = path.join(root, "identity-requested");
        await Promise.all([
          mkdir(installDirectory, { recursive: true }),
          mkdir(dataDirectory, { recursive: true }),
        ]);
        await writeFile(
          tokenFile,
          `${"a".repeat(32)}\r\nInjected: value`,
          "utf8",
        );
        const stopScript = path.resolve(
          import.meta.dirname,
          "..",
          "scripts",
          "release",
          "stop-daemon.ps1",
        );
        const quote = (value: string) => value.replaceAll("'", "''");
        const command = [
          `. '${quote(stopScript)}' -InstallDirectory '${quote(installDirectory)}'`,
          `$entrypoint = [IO.Path]::GetFullPath((Join-Path '${quote(installDirectory)}' 'app\\dist\\daemon\\main.js'))`,
          "$owner = [pscustomobject]@{ ProcessId = 1001; CreationMarker = '133713371337000001'; ExecutablePath = 'C:\\runtime\\node.exe'; Entrypoint = $entrypoint }",
          "function Test-LoopbackPortAvailable { param([int]$Port) return $false }",
          "function Get-ValidatedGatewayListenerOwner { param([int]$Port, [string[]]$Entrypoints) return $owner }",
          `function Request-AuthenticatedGatewayIdentity { param([int]$Port, [string]$BearerToken, [object]$Owner) Set-Content -LiteralPath '${quote(identityMarker)}' -Value 'called'; throw 'Identity must not be requested.' }`,
          "$blocked = $false",
          `try { Invoke-StopGatewayDaemon -InstallDirectory '${quote(installDirectory)}' -DataDirectory '${quote(dataDirectory)}' -TokenFile '${quote(tokenFile)}' -Port 32147 -TimeoutSeconds 1 } catch { if ($_.Exception.Message -notlike '*token file is invalid*') { throw }; $blocked = $true }`,
          "if (-not $blocked) { throw 'Header-injecting token was accepted.' }",
          `if (Test-Path -LiteralPath '${quote(identityMarker)}') { throw 'Identity was requested with an invalid token.' }`,
        ].join("; ");
        const result = spawnSync(
          "powershell.exe",
          [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
          ],
          { encoding: "utf8", timeout: 15_000, windowsHide: true },
        );
        expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
        await expect(readFile(identityMarker, "utf8")).rejects.toMatchObject({
          code: "ENOENT",
        });
      } finally {
        await rm(root, { force: true, recursive: true });
      }
    },
    30_000,
  );

  it.skipIf(process.platform !== "win32")(
    "does not contact a listener when multiple exact installed daemons run",
    async () => {
      const root = await mkdtemp(
        path.join(os.tmpdir(), "copilot-im-gateway-ambiguous-owner-"),
      );
      const installDirectory = path.join(root, "install");
      const dataDirectory = path.join(root, "data");
      const entrypoint = path.join(
        installDirectory,
        "app",
        "dist",
        "daemon",
        "main.js",
      );
      const tokenFile = path.join(dataDirectory, "auth-token");
      const readyA = path.join(root, "ready-a");
      const readyB = path.join(root, "ready-b");
      const requestB = path.join(root, "request-b");
      let daemonA: ChildProcess | undefined;
      let daemonB: ChildProcess | undefined;
      try {
        await Promise.all([
          mkdir(path.dirname(entrypoint), { recursive: true }),
          mkdir(dataDirectory, { recursive: true }),
        ]);
        await Promise.all([
          writeFile(
            entrypoint,
            [
              'const http = require("node:http");',
              'const fs = require("node:fs");',
              "const port = Number(process.argv[2]);",
              "const ready = process.argv[3];",
              "const received = process.argv[4];",
              "const server = http.createServer((_request, response) => {",
              '  fs.writeFileSync(received, "received");',
              "  response.writeHead(500);",
              '  response.end("unexpected");',
              "});",
              'server.listen(port, "127.0.0.1", () => {',
              '  fs.writeFileSync(ready, "ready");',
              "});",
              "",
            ].join("\n"),
            "utf8",
          ),
          writeFile(tokenFile, `${"a".repeat(64)}\n`, "utf8"),
        ]);
        const portA = await availablePort();
        daemonA = spawn(
          process.execPath,
          [entrypoint, String(portA), readyA, path.join(root, "request-a")],
          { stdio: "ignore", windowsHide: true },
        );
        await waitForFile(readyA);
        const portB = await availablePort();
        daemonB = spawn(
          process.execPath,
          [entrypoint, String(portB), readyB, requestB],
          { stdio: "ignore", windowsHide: true },
        );
        await waitForFile(readyB);

        const stopScript = path.resolve(
          import.meta.dirname,
          "..",
          "scripts",
          "release",
          "stop-daemon.ps1",
        );
        const blocked = spawnSync(
          "powershell.exe",
          [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            stopScript,
            "-InstallDirectory",
            installDirectory,
            "-DataDirectory",
            dataDirectory,
            "-TokenFile",
            tokenFile,
            "-Port",
            String(portB),
            "-TimeoutSeconds",
            "2",
          ],
          {
            encoding: "utf8",
            timeout: 15_000,
            windowsHide: true,
          },
        );
        expect(
          blocked.status,
          `${blocked.stdout}\n${blocked.stderr}`,
        ).not.toBe(0);
        expect(`${blocked.stdout}\n${blocked.stderr}`).toContain(
          "Expected one exact installed gateway process",
        );
        expect(daemonA.exitCode).toBeNull();
        expect(daemonB.exitCode).toBeNull();
        await expect(readFile(requestB, "utf8")).rejects.toMatchObject({
          code: "ENOENT",
        });
      } finally {
        if (daemonB !== undefined) {
          await stopTestProcess(daemonB);
        }
        if (daemonA !== undefined) {
          await stopTestProcess(daemonA);
        }
        await rm(root, { force: true, recursive: true });
      }
    },
    30_000,
  );

  it.skipIf(process.platform !== "win32")(
    "selects only an exact tokenized Node daemon entrypoint",
    async () => {
      const root = await mkdtemp(
        path.join(os.tmpdir(), "copilot-im-gateway-command-line-"),
      );
      const stopScript = path.join(
        path.resolve(import.meta.dirname, ".."),
        "scripts",
        "release",
        "stop-daemon.ps1",
      );
      const installDirectory = path.join(root, "fixture install");
      const entrypoint = path.join(
        installDirectory,
        "dist",
        "daemon",
        "main.js",
      );
      const quote = (value: string) => value.replaceAll("'", "''");
      try {
        await mkdir(path.dirname(entrypoint), { recursive: true });
        await writeFile(entrypoint, "export {};\n", "utf8");
        const command = [
          `. '${quote(stopScript)}' -InstallDirectory '${quote(installDirectory)}'`,
          `$entrypoint = [IO.Path]::GetFullPath('${quote(entrypoint)}')`,
          "$entrypoints = @($entrypoint)",
          `$node = '${quote(process.execPath)}'`,
          `$exact = [pscustomobject]@{ Name = 'node.exe'; ExecutablePath = $node; CommandLine = '"' + $node + '" "' + $entrypoint + '"' }`,
          `$substring = [pscustomobject]@{ Name = 'node.exe'; ExecutablePath = $node; CommandLine = '"' + $node + '" "' + $entrypoint + '.backup"' }`,
          `$optionValue = [pscustomobject]@{ Name = 'node.exe'; ExecutablePath = $node; CommandLine = '"' + $node + '" "--target=' + $entrypoint + '"' }`,
          `$workerArgument = [pscustomobject]@{ Name = 'node.exe'; ExecutablePath = $node; CommandLine = '"' + $node + '" "C:\\workers\\worker.js" "' + $entrypoint + '"' }`,
          `$wrongExecutable = [pscustomobject]@{ Name = 'gateway.exe'; ExecutablePath = $node; CommandLine = $exact.CommandLine }`,
          "if (-not (Test-GatewayProcess -Process $exact -Entrypoints $entrypoints)) { throw 'Exact daemon command line was rejected.' }",
          "if (Test-GatewayProcess -Process $substring -Entrypoints $entrypoints) { throw 'Substring command line was selected.' }",
          "if (Test-GatewayProcess -Process $optionValue -Entrypoints $entrypoints) { throw 'Option substring was selected.' }",
          "if (Test-GatewayProcess -Process $workerArgument -Entrypoints $entrypoints) { throw 'Daemon path in a worker argument was selected.' }",
          "if (Test-GatewayProcess -Process $wrongExecutable -Entrypoints $entrypoints) { throw 'Non-Node executable was selected.' }",
        ].join("; ");
        const result = spawnSync(
          "powershell.exe",
          [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
          ],
          { encoding: "utf8" },
        );
        expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      } finally {
        await rm(root, { force: true, recursive: true });
      }
    },
  );

  it.skipIf(process.platform !== "win32")(
    "encodes Unicode shutdown identity JSON and HMAC as UTF-8 on PowerShell 5.1",
    async () => {
      const root = await mkdtemp(
        path.join(os.tmpdir(), "copilot-im-gateway-unicode-identity-"),
      );
      try {
        const installDirectory = path.join(root, "安装 网关");
        const executablePath = path.join(root, "运行时", "节点.exe");
        const entrypoint = path.join(
          installDirectory,
          "应用",
          "dist",
          "daemon",
          "main.js",
        );
        const capturedBody = path.join(root, "identity-body.json");
        const stopScript = path.resolve(
          import.meta.dirname,
          "..",
          "scripts",
          "release",
          "stop-daemon.ps1",
        );
        const quote = (value: string) => value.replaceAll("'", "''");
        const token = "a".repeat(64);
        const nonce = "d".repeat(64);
        const command = [
          `. '${quote(stopScript)}' -InstallDirectory '${quote(installDirectory)}'`,
          `$owner = [pscustomobject]@{ ProcessId = 1001; CreationMarker = '133713371337000001'; ExecutablePath = '${quote(executablePath)}'; Entrypoint = '${quote(entrypoint)}' }`,
          `function New-GatewayShutdownNonce { return '${nonce}' }`,
          `function Invoke-WebRequest { param([string]$Uri, [string]$Method, [string]$ContentType, [object]$Body, [int]$TimeoutSec, [switch]$UseBasicParsing) if ($ContentType -cne 'application/json; charset=utf-8') { throw 'Unexpected identity content type.' }; if ($Body -isnot [byte[]]) { throw 'Identity body was not a byte array.' }; [IO.File]::WriteAllBytes('${quote(capturedBody)}', [byte[]]$Body); throw 'Captured identity request.' }`,
          `$identity = Request-AuthenticatedGatewayIdentity -Port 32147 -BearerToken '${token}' -Owner $owner`,
          "if ($null -ne $identity) { throw 'Capture-only identity request unexpectedly succeeded.' }",
        ].join("; ");
        const result = spawnSync(
          "powershell.exe",
          [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
          ],
          { encoding: "utf8", timeout: 15_000, windowsHide: true },
        );
        expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);

        const bodyBytes = await readFile(capturedBody);
        const bodyText = bodyBytes.toString("utf8");
        expect(Buffer.from(bodyText, "utf8")).toEqual(bodyBytes);
        expect(bodyBytes.length).toBeGreaterThan(bodyText.length);
        const payload = JSON.parse(bodyText) as {
          protocolVersion: number;
          owner: {
            pid: number;
            creationMarker: string;
            executablePath: string;
            entrypoint: string;
          };
          port: number;
          clientNonce: string;
          requestProof: string;
        };
        expect(payload).toMatchObject({
          protocolVersion: 1,
          owner: {
            pid: 1001,
            creationMarker: "133713371337000001",
            executablePath,
            entrypoint,
          },
          port: 32147,
          clientNonce: nonce,
        });
        const components = [
          "copilot-im-gateway-shutdown",
          "1",
          "identity-request",
          "1001",
          payload.owner.creationMarker,
          "32147",
          nonce,
          executablePath,
          entrypoint,
        ];
        const proofPayload = components
          .map((value) => `${Buffer.byteLength(value, "utf8")}:${value}`)
          .join("");
        expect(payload.requestProof).toBe(
          createHmac("sha256", token).update(proofPayload, "utf8").digest("hex"),
        );
      } finally {
        await rm(root, { force: true, recursive: true });
      }
    },
    30_000,
  );

  it.skipIf(process.platform !== "win32")(
    "maps the exact IPv4 loopback listener to its owning gateway process",
    async () => {
      const root = await mkdtemp(
        path.join(os.tmpdir(), "copilot-im-gateway-owner-map-"),
      );
      const installDirectory = path.join(root, "install");
      const entrypoint = path.join(
        installDirectory,
        "app",
        "dist",
        "daemon",
        "main.js",
      );
      const readyFile = path.join(root, "ready");
      let listener: ChildProcess | undefined;
      try {
        await mkdir(path.dirname(entrypoint), { recursive: true });
        await writeFile(
          entrypoint,
          [
            'const net = require("node:net");',
            'const fs = require("node:fs");',
            "const port = Number(process.argv[2]);",
            "const ready = process.argv[3];",
            "const server = net.createServer();",
            'server.listen(port, "127.0.0.1", () => {',
            '  fs.writeFileSync(ready, "ready");',
            "});",
            "",
          ].join("\n"),
          "utf8",
        );
        const port = await availablePort();
        listener = spawn(
          process.execPath,
          [entrypoint, String(port), readyFile],
          { stdio: "ignore", windowsHide: true },
        );
        await waitForFile(readyFile);

        const stopScript = path.resolve(
          import.meta.dirname,
          "..",
          "scripts",
          "release",
          "stop-daemon.ps1",
        );
        const quote = (value: string) => value.replaceAll("'", "''");
        const command = [
          `. '${quote(stopScript)}' -InstallDirectory '${quote(installDirectory)}'`,
          `$entrypoints = @([IO.Path]::GetFullPath('${quote(entrypoint)}'))`,
          `$owner = Get-ValidatedGatewayListenerOwner -Port ${port} -Entrypoints $entrypoints`,
          "$owner | ConvertTo-Json -Compress",
        ].join("; ");
        const result = spawnSync(
          "powershell.exe",
          [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
          ],
          { encoding: "utf8", timeout: 15_000, windowsHide: true },
        );
        expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
        const owner = JSON.parse(result.stdout.trim()) as {
          ProcessId: number;
          CreationMarker: string;
          ExecutablePath: string;
          Entrypoint: string;
        };
        expect(owner.ProcessId).toBe(listener.pid);
        expect(owner.CreationMarker).toMatch(/^[0-9]{1,20}$/u);
        expect(owner.ExecutablePath.toLowerCase()).toBe(
          realpathSync.native(process.execPath).toLowerCase(),
        );
        expect(owner.Entrypoint.toLowerCase()).toBe(
          realpathSync.native(entrypoint).toLowerCase(),
        );
      } finally {
        if (listener !== undefined) {
          await stopTestProcess(listener);
        }
        await rm(root, { force: true, recursive: true });
      }
    },
    30_000,
  );

  it.skipIf(process.platform !== "win32")(
    "connects before owner revalidation and never sends shutdown to a replacement listener",
    async () => {
      const root = await mkdtemp(
        path.join(os.tmpdir(), "copilot-im-gateway-owner-switch-"),
      );
      const listenerScript = path.join(root, "listener-race.cjs");
      const readyFile = path.join(root, "ready");
      const connectedFile = path.join(root, "connected");
      const replaceSignal = path.join(root, "replace");
      const replacementReady = path.join(root, "replacement-ready");
      const originalRequest = path.join(root, "original-request");
      const replacementRequest = path.join(root, "replacement-request");
      let listener: ChildProcess | undefined;
      try {
        const installDirectory = path.join(root, "install");
        await mkdir(installDirectory, { recursive: true });
        await writeFile(
          listenerScript,
          [
            'const fs = require("node:fs");',
            'const net = require("node:net");',
            "const port = Number(process.argv[2]);",
            "const readyFile = process.argv[3];",
            "const connectedFile = process.argv[4];",
            "const replaceSignal = process.argv[5];",
            "const replacementReady = process.argv[6];",
            "const originalRequest = process.argv[7];",
            "const replacementRequest = process.argv[8];",
            "let replacing = false;",
            "const replacement = net.createServer((socket) => {",
            '  fs.writeFileSync(replacementRequest, "connected");',
            "  socket.destroy();",
            "});",
            "const original = net.createServer((socket) => {",
            '  fs.writeFileSync(connectedFile, "connected");',
            "  let request = Buffer.alloc(0);",
            '  socket.on("data", (chunk) => {',
            "    request = Buffer.concat([request, chunk]);",
            '    const headerEnd = request.indexOf("\\r\\n\\r\\n");',
            "    if (headerEnd < 0) return;",
            "    const headers = request.subarray(0, headerEnd + 4).toString(\"ascii\");",
            '    const match = /\\r\\nContent-Length: ([0-9]+)\\r\\n/i.exec(headers);',
            "    if (match === null) return;",
            "    const bodyLength = Number(match[1]);",
            "    if (request.length < headerEnd + 4 + bodyLength) return;",
            "    fs.writeFileSync(originalRequest, request);",
            '    socket.end("HTTP/1.1 202 Accepted\\r\\nContent-Length: 17\\r\\nConnection: close\\r\\n\\r\\n{\\"accepted\\":true}");',
            "  });",
            "});",
            "const timer = setInterval(() => {",
            "  if (replacing || !fs.existsSync(replaceSignal)) return;",
            "  replacing = true;",
            "  original.close();",
            "  setTimeout(() => {",
            '    replacement.listen(port, "127.0.0.1", () => {',
            '      fs.writeFileSync(replacementReady, "ready");',
            "    });",
            "  }, 10);",
            "}, 10);",
            'original.listen(port, "127.0.0.1", () => {',
            '  fs.writeFileSync(readyFile, "ready");',
            "});",
            "process.on(\"exit\", () => clearInterval(timer));",
            "",
          ].join("\n"),
          "utf8",
        );
        const port = await availablePort();
        listener = spawn(
          process.execPath,
          [
            listenerScript,
            String(port),
            readyFile,
            connectedFile,
            replaceSignal,
            replacementReady,
            originalRequest,
            replacementRequest,
          ],
          { stdio: "ignore", windowsHide: true },
        );
        await waitForFile(readyFile);

        const stopScript = path.resolve(
          import.meta.dirname,
          "..",
          "scripts",
          "release",
          "stop-daemon.ps1",
        );
        const quote = (value: string) => value.replaceAll("'", "''");
        const command = [
          `. '${quote(stopScript)}' -InstallDirectory '${quote(installDirectory)}'`,
          `$entrypoint = [IO.Path]::GetFullPath((Join-Path '${quote(installDirectory)}' 'app\\dist\\daemon\\main.js'))`,
          "$ownerA = [pscustomobject]@{ ProcessId = 1001; CreationMarker = '133713371337000001'; ExecutablePath = 'C:\\runtime\\node.exe'; Entrypoint = $entrypoint }",
          "$script:ownerReads = 0",
          `function Get-ValidatedGatewayListenerOwner { param([int]$Port, [string[]]$Entrypoints) $script:ownerReads += 1; $deadline = [DateTime]::UtcNow.AddSeconds(5); while (-not (Test-Path -LiteralPath '${quote(connectedFile)}')) { if ([DateTime]::UtcNow -ge $deadline) { throw 'Owner resolution ran before the TCP connection was accepted.' }; Start-Sleep -Milliseconds 10 }; Set-Content -LiteralPath '${quote(replaceSignal)}' -Value 'replace'; while (-not (Test-Path -LiteralPath '${quote(replacementReady)}')) { if ([DateTime]::UtcNow -ge $deadline) { throw 'Replacement listener did not start.' }; Start-Sleep -Milliseconds 10 }; return $ownerA }`,
          "$challenge = [pscustomobject]@{ ProtocolVersion = 1; InstanceId = '11111111-1111-4111-8111-111111111111'; ChallengeId = '22222222-2222-4222-8222-222222222222'; ClientNonce = ('b' * 64); ResponseProof = ('c' * 64) }",
          `$accepted = Invoke-AuthenticatedGatewayShutdown -Port ${port} -BearerToken ('a' * 64) -Challenge $challenge -ExpectedOwner $ownerA -Entrypoints @($entrypoint)`,
          "if (-not $accepted) { throw 'The original connected listener did not accept shutdown.' }",
          "if ($script:ownerReads -ne 1) { throw 'Listener owner was not resolved exactly once after connect.' }",
        ].join("; ");
        const result = spawnSync(
          "powershell.exe",
          [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
          ],
          { encoding: "utf8", timeout: 15_000, windowsHide: true },
        );
        expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
        const sentRequest = await readFile(originalRequest, "utf8");
        expect(sentRequest).toContain("POST /v2/admin/shutdown HTTP/1.1");
        expect(sentRequest).toContain(`Authorization: Bearer ${"a".repeat(64)}`);
        await expect(readFile(replacementRequest, "utf8")).rejects.toMatchObject({
          code: "ENOENT",
        });
      } finally {
        if (listener !== undefined) {
          await stopTestProcess(listener);
        }
        await rm(root, { force: true, recursive: true });
      }
    },
    30_000,
  );
});
