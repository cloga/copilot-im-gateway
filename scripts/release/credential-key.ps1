param(
    [string]$DataDirectory,
    [switch]$ProvisionNext,
    [string]$NodePath,
    [string]$EntryPoint
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ([string]::IsNullOrWhiteSpace($DataDirectory)) {
    if (-not [string]::IsNullOrWhiteSpace($env:COPILOT_IM_GATEWAY_DATA_DIR)) {
        $DataDirectory = $env:COPILOT_IM_GATEWAY_DATA_DIR
    }
    else {
        $DataDirectory = Join-Path $HOME ".copilot-im-gateway"
    }
}

$resolvedDataDirectory = [IO.Path]::GetFullPath($DataDirectory)
$keyPath = Join-Path $resolvedDataDirectory "credential-master-key"
if ($ProvisionNext) {
    $keyPath = "$keyPath.next"
}
$databasePath = Join-Path $resolvedDataDirectory "gateway.sqlite"
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
if ($null -eq $currentSid) {
    throw "Unable to resolve the current Windows operator SID."
}

function New-OperatorDirectorySecurity {
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($currentSid)
    $security.SetAccessRuleProtection($true, $false)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $currentSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit",
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $security.AddAccessRule($rule)
    return $security
}

function New-OperatorFileSecurity {
    $security = [Security.AccessControl.FileSecurity]::new()
    $security.SetOwner($currentSid)
    $security.SetAccessRuleProtection($true, $false)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $currentSid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $security.AddAccessRule($rule)
    return $security
}

function Assert-OperatorOnlyAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$Directory
    )

    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Credential key path cannot be a reparse point."
    }
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) {
        throw "Credential key ACL inheritance is not disabled."
    }
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier])
    if ($owner.Value -ne $currentSid.Value) {
        throw "Credential key path is not owned by the current operator."
    }
    $rules = @($acl.GetAccessRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier]
    ))
    if ($rules.Count -ne 1) {
        throw "Credential key ACL must contain exactly one operator rule."
    }
    $rule = $rules[0]
    if (
        $rule.IdentityReference.Value -ne $currentSid.Value -or
        $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $rule.IsInherited -or
        (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
            [Security.AccessControl.FileSystemRights]::FullControl)
    ) {
        throw "Credential key ACL grants access beyond the current operator."
    }
    if ($Directory -and $item.PSIsContainer -ne $true) {
        throw "Credential key parent is not a directory."
    }
    if (-not $Directory -and $item.PSIsContainer) {
        throw "Credential master key is not a file."
    }
}

function Get-SqliteUserVersion {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return 0
    }
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite
    )
    try {
        if ($stream.Length -lt 64) {
            throw "Gateway database header is incomplete."
        }
        $stream.Position = 60
        $bytes = [byte[]]::new(4)
        if ($stream.Read($bytes, 0, 4) -ne 4) {
            throw "Gateway database user version could not be read."
        }
        return (
            ([int]$bytes[0] -shl 24) -bor
            ([int]$bytes[1] -shl 16) -bor
            ([int]$bytes[2] -shl 8) -bor
            [int]$bytes[3]
        )
    }
    finally {
        $stream.Dispose()
    }
}

if (-not (Test-Path -LiteralPath $resolvedDataDirectory -PathType Container)) {
    [IO.Directory]::CreateDirectory($resolvedDataDirectory) | Out-Null
}
$dataDirectoryItem = Get-Item -LiteralPath $resolvedDataDirectory -Force
if (($dataDirectoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Credential key parent cannot be a reparse point."
}
$directoryInfo = [IO.DirectoryInfo]::new($resolvedDataDirectory)
$directoryInfo.SetAccessControl((New-OperatorDirectorySecurity))
Assert-OperatorOnlyAcl -Path $resolvedDataDirectory -Directory $true

if (-not (Test-Path -LiteralPath $keyPath -PathType Leaf)) {
    if (-not $ProvisionNext -and (Get-SqliteUserVersion -Path $databasePath) -ge 4) {
        throw "Credential master key is missing for an encrypted gateway database."
    }
    $temporaryPath = "$keyPath.create-$PID"
    $key = [byte[]]::new(32)
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($key)
        $stream = [IO.File]::Open(
            $temporaryPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None
        )
        try {
            $stream.Write($key, 0, $key.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        $fileInfo = [IO.FileInfo]::new($temporaryPath)
        $fileInfo.SetAccessControl((New-OperatorFileSecurity))
        Assert-OperatorOnlyAcl -Path $temporaryPath -Directory $false
        [IO.File]::Move($temporaryPath, $keyPath)
    }
    finally {
        [Array]::Clear($key, 0, $key.Length)
        $random.Dispose()
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

Assert-OperatorOnlyAcl -Path $keyPath -Directory $false
if ((Get-Item -LiteralPath $keyPath).Length -ne 32) {
    throw "Credential master key has an invalid length."
}

$env:COPILOT_IM_GATEWAY_WINDOWS_KEY_ACL = "operator-only-v1"
if (-not [string]::IsNullOrWhiteSpace($NodePath)) {
    if ([string]::IsNullOrWhiteSpace($EntryPoint)) {
        throw "EntryPoint is required when NodePath is provided."
    }
    & $NodePath $EntryPoint
    exit $LASTEXITCODE
}
