param(
    [string]$DataDirectory,
    [string]$TokenFile,
    [int]$Port = -1
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Assert-Command {
    param([Parameter(Mandatory = $true)][string]$Name)

    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found."
    }
}

Assert-Command "node"
Assert-Command "npm"

$nodeVersionText = (& node --version).Trim().TrimStart("v")
$nodeVersion = [Version]$nodeVersionText
$supportedNode = (
    ($nodeVersion.Major -eq 22 -and $nodeVersion.Minor -ge 13) -or
    $nodeVersion.Major -ge 24
)
if (-not $supportedNode) {
    throw "Node.js 22.13+ (excluding 23.x) or 24+ is required; found $nodeVersionText."
}

$copilotRoot = Join-Path $HOME ".copilot"
$installDirectory = Join-Path $copilotRoot "im-gateway"
$extensionDirectory = Join-Path $copilotRoot "extensions\im-gateway"
$stagingDirectory = Join-Path $copilotRoot ("im-gateway-install-" + [Guid]::NewGuid())

try {
    New-Item -ItemType Directory -Path $stagingDirectory -Force | Out-Null
    Get-ChildItem -LiteralPath $PSScriptRoot -Force |
        Where-Object { $_.Name -ne "node_modules" } |
        Copy-Item -Destination $stagingDirectory -Recurse -Force

    Push-Location $stagingDirectory
    try {
        & npm ci --omit=dev --ignore-scripts
        if ($LASTEXITCODE -ne 0) {
            throw "npm ci failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }

    $stopParameters = @{ InstallDirectory = $installDirectory }
    if ($PSBoundParameters.ContainsKey("DataDirectory")) {
        $stopParameters.DataDirectory = $DataDirectory
    }
    if ($PSBoundParameters.ContainsKey("TokenFile")) {
        $stopParameters.TokenFile = $TokenFile
    }
    if ($PSBoundParameters.ContainsKey("Port")) {
        $stopParameters.Port = $Port
    }
    try {
        & (Join-Path $PSScriptRoot "stop-daemon.ps1") @stopParameters
    }
    catch {
        throw "Upgrade aborted before replacing installed files. $($_.Exception.Message)"
    }

    if (Test-Path -LiteralPath $installDirectory) {
        Remove-Item -LiteralPath $installDirectory -Recurse -Force
    }
    Move-Item -LiteralPath $stagingDirectory -Destination $installDirectory

    if (Test-Path -LiteralPath $extensionDirectory) {
        Remove-Item -LiteralPath $extensionDirectory -Recurse -Force
    }
    New-Item -ItemType Directory -Path $extensionDirectory -Force | Out-Null
    Copy-Item `
        -Path (Join-Path $installDirectory ".github\extensions\im-gateway\*") `
        -Destination $extensionDirectory `
        -Recurse `
        -Force
}
finally {
    if (Test-Path -LiteralPath $stagingDirectory) {
        Remove-Item -LiteralPath $stagingDirectory -Recurse -Force
    }
}

Write-Host "Installed Copilot IM Gateway at $installDirectory"
Write-Host "Installed Copilot extension at $extensionDirectory"
Write-Host "Start with: & `"$installDirectory\start.ps1`""
