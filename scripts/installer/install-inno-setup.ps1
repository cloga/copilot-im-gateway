$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$version = "7.1.0"
$expectedSha256 = "0362a383ed217d4c4239b5933866dd96d3eb2102737da92f80f6057a4b40df2f"
$downloadUrl = "https://github.com/jrsoftware/issrc/releases/download/is-7_1_0/innosetup-7.1.0-x64.exe"
$toolsDirectory = Join-Path ([IO.Path]::GetTempPath()) "copilot-im-gateway-tools"
$installerPath = Join-Path $toolsDirectory "innosetup-$version-x64.exe"
$installDirectory = Join-Path $toolsDirectory "inno-setup-$version"
$compilerPath = Join-Path $installDirectory "ISCC.exe"

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

New-Item -ItemType Directory -Path $toolsDirectory -Force | Out-Null
if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath
}

$actualSha256 = Get-Sha256 -Path $installerPath
if ($actualSha256 -ne $expectedSha256) {
    Remove-Item -LiteralPath $installerPath -Force
    throw "Inno Setup download checksum mismatch."
}

if (-not (Test-Path -LiteralPath $compilerPath -PathType Leaf)) {
    $process = Start-Process -FilePath $installerPath -ArgumentList @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/CURRENTUSER",
        "/DIR=$installDirectory"
    ) -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "Inno Setup installation failed with exit code $($process.ExitCode)."
    }
}

if (-not (Test-Path -LiteralPath $compilerPath -PathType Leaf)) {
    throw "Inno Setup compiler was not installed at the expected path."
}

Write-Output $compilerPath
