import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  assertBuildOutput,
  createDeterministicZip,
  writeChecksum,
} from "../scripts/package-release.mjs";
import {
  daemonRuntimeManifest,
  findRelativeEsmSpecifiers,
  writeEsmClosureManifest,
} from "../scripts/release/esm-closure.mjs";
import {
  requiredEntries,
  validateReleaseArchive,
} from "../scripts/validate-release.mjs";

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
    const firstArchive = path.join(root, "first.zip");
    const secondArchive = path.join(root, "second.zip");
    const incompleteArchive = path.join(root, "incomplete.zip");
    const missingStoreArchive = path.join(root, "missing-store.zip");
    const missingChannelArchive = path.join(root, "missing-channel.zip");
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
      ]);

      await createDeterministicZip(firstStage, firstArchive);
      await createDeterministicZip(secondStage, secondArchive);
      await createDeterministicZip(missingStoreStage, missingStoreArchive);
      await createDeterministicZip(missingChannelStage, missingChannelArchive);
      const firstChecksum = await writeChecksum(firstArchive);
      const secondChecksum = await writeChecksum(secondArchive);
      const missingStoreChecksum = await writeChecksum(missingStoreArchive);
      const missingChannelChecksum = await writeChecksum(missingChannelArchive);

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
    expect(installer).toContain("PrivilegesRequired=lowest");
    expect(installer).toContain("ArchitecturesAllowed=x64compatible");
    expect(installer).toContain("Copilot-IM-Gateway-Setup-v{#AppVersion}-x64");
    expect(installer).not.toContain("runascurrentuser");
    expect(installer).toContain("PrepareToInstall");
    expect(installer).toContain("ExtractTemporaryFile('stop-daemon.ps1')");
    expect(releaseWorkflow).toContain("npm run release:installer:smoke");
    expect(releaseWorkflow).toContain("release/*.exe");
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
    expect(stopDaemonScript).toContain("Stop-Process -Id $processId");
    expect(stopDaemonScript).toContain("Wait-Process -Id $processId");
    expect(stopDaemonScript).toContain("CommandLineToArgvW");
    expect(stopDaemonScript).toContain("Test-GatewayProcess");
    expect(stopDaemonScript).toContain("Get-RevalidatedGatewayProcess");
    expect(stopDaemonScript).toContain("/v2/admin/shutdown");
    expect(stopDaemonScript).toContain(
      "Start-Sleep -Seconds $FallbackLeaseWaitSeconds",
    );
    expect(stopDaemonScript).not.toContain("$commandLine.IndexOf");
    expect(stopDaemonScript).toContain(
      "[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)",
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
  });

  it.skipIf(process.platform !== "win32")(
    "selects only an exact tokenized Node daemon entrypoint",
    () => {
      const root = path.resolve(import.meta.dirname, "..");
      const stopScript = path.join(
        root,
        "scripts",
        "release",
        "stop-daemon.ps1",
      );
      const installDirectory = path.join(root, "fixture install");
      const quote = (value: string) => value.replaceAll("'", "''");
      const command = [
        `. '${quote(stopScript)}' -InstallDirectory '${quote(installDirectory)}'`,
        `$entrypoint = [IO.Path]::GetFullPath('${quote(path.join(installDirectory, "dist", "daemon", "main.js"))}')`,
        "$entrypoints = @($entrypoint)",
        `$exact = [pscustomobject]@{ Name = 'node.exe'; ExecutablePath = 'C:\\Program Files\\nodejs\\node.exe'; CommandLine = '"C:\\Program Files\\nodejs\\node.exe" "' + $entrypoint + '"' }`,
        `$substring = [pscustomobject]@{ Name = 'node.exe'; ExecutablePath = 'C:\\Program Files\\nodejs\\node.exe'; CommandLine = '"C:\\Program Files\\nodejs\\node.exe" "' + $entrypoint + '.backup"' }`,
        `$optionValue = [pscustomobject]@{ Name = 'node.exe'; ExecutablePath = 'C:\\Program Files\\nodejs\\node.exe'; CommandLine = '"C:\\Program Files\\nodejs\\node.exe" "--target=' + $entrypoint + '"' }`,
        `$workerArgument = [pscustomobject]@{ Name = 'node.exe'; ExecutablePath = 'C:\\Program Files\\nodejs\\node.exe'; CommandLine = '"C:\\Program Files\\nodejs\\node.exe" "C:\\workers\\worker.js" "' + $entrypoint + '"' }`,
        `$wrongExecutable = [pscustomobject]@{ Name = 'gateway.exe'; ExecutablePath = 'C:\\Program Files\\nodejs\\node.exe'; CommandLine = $exact.CommandLine }`,
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
    },
  );
});
