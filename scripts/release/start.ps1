$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$entrypoint = Join-Path $PSScriptRoot "dist\daemon\main.js"
if (-not (Test-Path -LiteralPath $entrypoint -PathType Leaf)) {
    throw "Gateway entrypoint is missing. Reinstall the release package."
}

& node $entrypoint
exit $LASTEXITCODE
