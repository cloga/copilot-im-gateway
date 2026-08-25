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

function Assert-InstallerRejectsPort {
    param([Parameter(Mandatory = $true)][string]$Value)

    $suffix = [Guid]::NewGuid().ToString("N")
    $rejected = Start-Process -FilePath $resolvedInstallerPath -ArgumentList @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/DIR=$(Join-Path $root "invalid-$suffix")",
        "/EXTENSIONDIR=$(Join-Path $root "invalid-extension-$suffix")",
        "/GATEWAYPORT=$Value"
    ) -Wait -PassThru
    if ($rejected.ExitCode -eq 0) {
        throw "Silent installer accepted invalid gateway port '$Value'."
    }
}

try {
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    foreach ($invalidPort in @("not-a-number", "-1", "65536")) {
        Assert-InstallerRejectsPort -Value $invalidPort
    }
    $install = Start-Process -FilePath $resolvedInstallerPath -ArgumentList @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/DIR=$installDirectory",
        "/EXTENSIONDIR=$extensionDirectory",
        "/GATEWAYPORT=0"
    ) -Wait -PassThru
    if ($install.ExitCode -ne 0) {
        throw "Silent installer failed with exit code $($install.ExitCode)."
    }

    foreach ($expectedFile in @(
        "runtime\node.exe",
        "app\daemon-runtime-closure.json",
        "app\dist\daemon\main.js",
        "app\node_modules\zod\package.json",
        "start-daemon.cmd",
        "unins000.exe"
    )) {
        if (-not (Test-Path -LiteralPath (Join-Path $installDirectory $expectedFile) -PathType Leaf)) {
            throw "Installed file is missing: $expectedFile"
        }
    }
    foreach ($extensionFile in @("extension.mjs", "extension-runtime.mjs", "canvas.mjs", "gateway-client.mjs")) {
        if (-not (Test-Path -LiteralPath (Join-Path $extensionDirectory $extensionFile) -PathType Leaf)) {
            throw "Installed extension file is missing: $extensionFile"
        }
    }
    $installedNode = Join-Path $installDirectory "runtime\node.exe"
    $closureHelper = Join-Path $repositoryRoot "scripts\release\esm-closure.mjs"
    & $installedNode `
        $closureHelper `
        verify `
        (Join-Path $installDirectory "app") `
        (Join-Path $installDirectory "app\daemon-runtime-closure.json")
    if ($LASTEXITCODE -ne 0) {
        throw "Installed daemon runtime closure validation failed."
    }
    & $installedNode $closureHelper check $extensionDirectory "extension.mjs"
    if ($LASTEXITCODE -ne 0) {
        throw "Installed extension runtime closure validation failed."
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

    $upgrade = Start-Process -FilePath $resolvedInstallerPath -ArgumentList @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/DIR=$installDirectory",
        "/EXTENSIONDIR=$extensionDirectory",
        "/GATEWAYDATADIR=$dataDirectory",
        "/GATEWAYPORT=$port"
    ) -Wait -PassThru
    if ($upgrade.ExitCode -ne 0) {
        throw "Silent upgrade failed with exit code $($upgrade.ExitCode)."
    }
    if (-not $daemon.WaitForExit(30000)) {
        throw "Upgrade did not terminate the old daemon process."
    }
    if ($daemon.ExitCode -ne 0) {
        throw "Upgrade did not gracefully shut down the old daemon process."
    }
    $portProbe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $port)
    try {
        $portProbe.Start()
    }
    catch {
        throw "Upgrade did not wait for loopback port release."
    }
    finally {
        $portProbe.Stop()
    }

    $daemon = [Diagnostics.Process]::Start($startInfo)
    Wait-ForHealth -Port $port
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
