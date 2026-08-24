param(
    [string]$InstallerPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    $version = (Get-Content (Join-Path $repositoryRoot "package.json") -Raw | ConvertFrom-Json).version
    $InstallerPath = Join-Path $repositoryRoot "release\Copilot-IM-Gateway-Setup-v$version-x64.exe"
}
$resolvedInstallerPath = (Resolve-Path $InstallerPath).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ("copilot-im-gateway-smoke-" + [Guid]::NewGuid())
$installDirectory = Join-Path $root "install"
$extensionDirectory = Join-Path $root "extension"
$dataDirectory = Join-Path $root "data"
$daemon = $null

function Wait-ForHealth {
    param([int]$Port)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/healthz" -UseBasicParsing
            if ($response.StatusCode -eq 200) {
                return
            }
        }
        catch {
            Start-Sleep -Milliseconds 250
        }
    }
    throw "Installed daemon did not become healthy."
}

try {
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $install = Start-Process -FilePath $resolvedInstallerPath -ArgumentList @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/DIR=$installDirectory",
        "/EXTENSIONDIR=$extensionDirectory"
    ) -Wait -PassThru
    if ($install.ExitCode -ne 0) {
        throw "Silent installer failed with exit code $($install.ExitCode)."
    }

    foreach ($expectedFile in @(
        "runtime\node.exe",
        "app\dist\daemon\main.js",
        "app\node_modules\zod\package.json",
        "start-daemon.cmd",
        "unins000.exe"
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $installDirectory $expectedFile) -PathType Leaf)) {
            throw "Installed file is missing: $expectedFile"
        }
    }
    foreach ($extensionFile in @("extension.mjs", "canvas.mjs", "gateway-client.mjs")) {
        if (-not (Test-Path -LiteralPath (Join-Path $extensionDirectory $extensionFile) -PathType Leaf)) {
            throw "Installed extension file is missing: $extensionFile"
        }
    }

    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()

    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = Join-Path $installDirectory "runtime\node.exe"
    $startInfo.Arguments = '"' + (Join-Path $installDirectory "app\dist\daemon\main.js") + '"'
    $startInfo.WorkingDirectory = Join-Path $installDirectory "app"
    $startInfo.UseShellExecute = $false
    $startInfo.Environment["COPILOT_IM_GATEWAY_DATA_DIR"] = $dataDirectory
    $startInfo.Environment["COPILOT_IM_GATEWAY_PORT"] = [string]$port
    $daemon = [Diagnostics.Process]::Start($startInfo)
    Wait-ForHealth -Port $port

    try {
        Invoke-WebRequest -Uri "http://127.0.0.1:$port/v1/status" -UseBasicParsing | Out-Null
        throw "Authenticated endpoint unexpectedly allowed an anonymous request."
    }
    catch {
        if ($_.Exception.Response.StatusCode.value__ -ne 401) {
            throw
        }
    }
}
finally {
    if ($null -ne $daemon -and -not $daemon.HasExited) {
        $daemon.Kill()
        $daemon.WaitForExit()
    }
    $uninstaller = Join-Path $installDirectory "unins000.exe"
    if (Test-Path -LiteralPath $uninstaller -PathType Leaf) {
        $uninstall = Start-Process -FilePath $uninstaller -ArgumentList @(
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART"
        ) -Wait -PassThru
        if ($uninstall.ExitCode -ne 0) {
            throw "Silent uninstaller failed with exit code $($uninstall.ExitCode)."
        }
    }
    if (Test-Path -LiteralPath $installDirectory) {
        throw "Uninstaller did not remove the application directory."
    }
    if (Test-Path -LiteralPath $extensionDirectory) {
        throw "Uninstaller did not remove the installed extension directory."
    }
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}

Write-Output "Windows installer smoke test passed."
