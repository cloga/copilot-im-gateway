param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\..\release"),
    [string]$IsccPath = $env:ISCC_PATH
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$nodeVersion = "24.11.1"
$nodeArchiveName = "node-v$nodeVersion-win-x64.zip"
$nodeArchiveSha256 = "5355ae6d7c49eddcfde7d34ac3486820600a831bf81dc3bdca5c8db6a9bb0e76"
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$manifest = Get-Content (Join-Path $repositoryRoot "package.json") -Raw | ConvertFrom-Json
$version = [string]$manifest.version
$entrypoint = Join-Path $repositoryRoot "dist\daemon\main.js"

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::OpenRead($Path)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($stream))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
        $stream.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $entrypoint -PathType Leaf)) {
    throw "Release build output is missing: dist\daemon\main.js. Run npm run build first."
}
if ([string]::IsNullOrWhiteSpace($IsccPath) -or -not (Test-Path -LiteralPath $IsccPath -PathType Leaf)) {
    throw "ISCC_PATH must point to the pinned Inno Setup compiler. Run scripts\installer\install-inno-setup.ps1 first."
}

$resolvedOutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force | Out-Null
$workDirectory = Join-Path ([IO.Path]::GetTempPath()) ("copilot-im-gateway-installer-" + [Guid]::NewGuid())
$stageDirectory = Join-Path $workDirectory "stage"
$applicationDirectory = Join-Path $stageDirectory "app"
$runtimeDirectory = Join-Path $stageDirectory "runtime"
$extensionDirectory = Join-Path $stageDirectory "extension"
$nodeArchivePath = Join-Path $workDirectory $nodeArchiveName

try {
    New-Item -ItemType Directory -Path $applicationDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $extensionDirectory -Force | Out-Null

    foreach ($entry in @("dist", "docs")) {
        Copy-Item -LiteralPath (Join-Path $repositoryRoot $entry) -Destination $applicationDirectory -Recurse -Force
    }
    foreach ($entry in @("package.json", "package-lock.json", "README.md", "THIRD_PARTY_NOTICES.md")) {
        Copy-Item -LiteralPath (Join-Path $repositoryRoot $entry) -Destination $applicationDirectory -Force
    }
    $closureHelper = Join-Path $repositoryRoot "scripts\release\esm-closure.mjs"
    $closureManifest = Join-Path $applicationDirectory "daemon-runtime-closure.json"
    & node $closureHelper write $applicationDirectory $closureManifest
    if ($LASTEXITCODE -ne 0) {
        throw "Daemon runtime closure generation failed with exit code $LASTEXITCODE."
    }
    Copy-Item -Path (Join-Path $repositoryRoot ".github\extensions\im-gateway\*") -Destination $extensionDirectory -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $repositoryRoot "scripts\release\stop-daemon.ps1") -Destination $stageDirectory
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "start-daemon.cmd") -Destination $stageDirectory
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "open-status.cmd") -Destination $stageDirectory

    Invoke-WebRequest -Uri "https://nodejs.org/dist/v$nodeVersion/$nodeArchiveName" -OutFile $nodeArchivePath
    $actualNodeSha256 = Get-Sha256 -Path $nodeArchivePath
    if ($actualNodeSha256 -ne $nodeArchiveSha256) {
        throw "Node.js runtime checksum mismatch."
    }

    Expand-Archive -LiteralPath $nodeArchivePath -DestinationPath $workDirectory
    Move-Item -LiteralPath (Join-Path $workDirectory "node-v$nodeVersion-win-x64") -Destination $runtimeDirectory

    $npmCli = Join-Path $runtimeDirectory "node_modules\npm\bin\npm-cli.js"
    & (Join-Path $runtimeDirectory "node.exe") $npmCli ci --omit=dev --ignore-scripts --prefix $applicationDirectory
    if ($LASTEXITCODE -ne 0) {
        throw "Production dependency installation failed with exit code $LASTEXITCODE."
    }
    Remove-Item -LiteralPath (Join-Path $runtimeDirectory "node_modules") -Recurse -Force
    foreach ($runtimeTool in @("corepack", "corepack.cmd", "npm", "npm.cmd", "npx", "npx.cmd")) {
        $runtimeToolPath = Join-Path $runtimeDirectory $runtimeTool
        if (Test-Path -LiteralPath $runtimeToolPath) {
            Remove-Item -LiteralPath $runtimeToolPath -Force
        }
    }

    & $IsccPath `
        "/Qp" `
        "/DAppVersion=$version" `
        "/DStageDir=$stageDirectory" `
        "/DOutputDir=$resolvedOutputDirectory" `
        (Join-Path $PSScriptRoot "windows-installer.iss")
    if ($LASTEXITCODE -ne 0) {
        throw "Inno Setup compilation failed with exit code $LASTEXITCODE."
    }

    $installerName = "Copilot-IM-Gateway-Setup-v$version-x64.exe"
    $installerPath = Join-Path $resolvedOutputDirectory $installerName
    if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
        throw "Expected installer was not created: $installerPath"
    }
    $digest = Get-Sha256 -Path $installerPath
    Set-Content -LiteralPath "$installerPath.sha256" -Value "$digest  $installerName" -Encoding ascii
    Write-Output $installerPath
}
finally {
    if (Test-Path -LiteralPath $workDirectory) {
        Remove-Item -LiteralPath $workDirectory -Recurse -Force
    }
}
