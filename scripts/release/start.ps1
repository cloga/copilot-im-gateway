$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$entrypoint = Join-Path $PSScriptRoot "dist\daemon\main.js"
$keyHelper = Join-Path $PSScriptRoot "credential-key.ps1"
if (-not (Test-Path -LiteralPath $entrypoint -PathType Leaf)) {
    throw "Gateway entrypoint is missing. Reinstall the release package."
}

if ($env:OS -eq "Windows_NT") {
    & $keyHelper -NodePath (Get-Command node).Source -EntryPoint $entrypoint
}
else {
    & node $entrypoint
}
exit $LASTEXITCODE
