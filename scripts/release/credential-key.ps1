param(
    [string]$DataDirectory,
    [switch]$ProvisionNext,
    [switch]$Rotate,
    [switch]$RecoverRotation,
    [string]$NodePath,
    [string]$EntryPoint,
    [string]$MaintenanceEntryPoint
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
Import-Module (
    Join-Path $PSHOME "Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1"
) -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($DataDirectory)) {
    if (-not [string]::IsNullOrWhiteSpace($env:COPILOT_IM_GATEWAY_DATA_DIR)) {
        $DataDirectory = $env:COPILOT_IM_GATEWAY_DATA_DIR
    }
    else {
        $DataDirectory = Join-Path $HOME ".copilot-im-gateway"
    }
}

$resolvedDataDirectory = [IO.Path]::GetFullPath($DataDirectory)
$canonicalKeyPath = Join-Path $resolvedDataDirectory "credential-master-key"
$nextKeyPath = "$canonicalKeyPath.next"
$previousKeyPath = "$canonicalKeyPath.previous"
$rotationPath = "$canonicalKeyPath.rotation"
$retiredKeyPath = "$canonicalKeyPath.retired"
$abortedKeyPath = "$canonicalKeyPath.aborted"
$completedRotationPath = "$canonicalKeyPath.rotation-completed"
$databasePath = Join-Path $resolvedDataDirectory "gateway.sqlite"
$moveFileReplaceExisting = 1
$moveFileWriteThrough = 8
$zeroKeyId = "66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
if ($null -eq $currentSid) {
    throw "Unable to resolve the current Windows operator SID."
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class GatewayDurableMove {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool MoveFileEx(
        string existingFileName,
        string newFileName,
        int flags
    );
}
"@

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

function Move-DurableFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [switch]$Replace
    )

    if ([IO.Path]::GetDirectoryName($Source) -ne [IO.Path]::GetDirectoryName($Destination)) {
        throw "Credential rotation files must remain in the protected data directory."
    }
    if ($Replace -and (Test-Path -LiteralPath $Destination -PathType Leaf)) {
        Assert-OperatorOnlyAcl -Path $Destination -Directory $false
    }
    elseif (Test-Path -LiteralPath $Destination) {
        throw "Credential rotation destination already exists."
    }
    $flags = $moveFileWriteThrough
    if ($Replace) {
        $flags = $flags -bor $moveFileReplaceExisting
    }
    if (-not [GatewayDurableMove]::MoveFileEx($Source, $Destination, $flags)) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Credential rotation metadata could not be durably moved (Windows error $errorCode)."
    }
    if (
        (Test-Path -LiteralPath $Source) -or
        -not (Test-Path -LiteralPath $Destination -PathType Leaf)
    ) {
        throw "Credential rotation metadata move could not be verified."
    }
    Assert-OperatorOnlyAcl -Path $Destination -Directory $false
}

function New-ProtectedKey {
    param([Parameter(Mandatory = $true)][string]$Path)

    $temporaryPath = "$Path.create-$PID"
    $key = [byte[]]::new(32)
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($key)
        $stream = [IO.FileStream]::new(
            $temporaryPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough
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
        Move-DurableFile -Source $temporaryPath -Destination $Path
    }
    finally {
        [Array]::Clear($key, 0, $key.Length)
        $random.Dispose()
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Assert-ProtectedKey {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-OperatorOnlyAcl -Path $Path -Directory $false
    if ((Get-Item -LiteralPath $Path).Length -ne 32) {
        throw "Credential master key has an invalid length."
    }
}

function Get-KeyId {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-ProtectedKey -Path $Path
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($stream)
        try {
            return (($hash | ForEach-Object { $_.ToString("x2") }) -join "")
        }
        finally {
            [Array]::Clear($hash, 0, $hash.Length)
        }
    }
    finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Get-OptionalKeyId {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }
    return Get-KeyId -Path $Path
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

function Read-RotationJournal {
    Assert-OperatorOnlyAcl -Path $rotationPath -Directory $false
    $raw = [IO.File]::ReadAllText($rotationPath, [Text.Encoding]::UTF8)
    $pattern = '^\{"version":1,"currentKeyId":"([a-f0-9]{64})","nextKeyId":"([a-f0-9]{64})"\}\r?\n$'
    if ($raw -notmatch $pattern -or $Matches[1] -eq $Matches[2]) {
        throw "Credential rotation journal is invalid."
    }
    return @{
        CurrentKeyId = $Matches[1]
        NextKeyId = $Matches[2]
    }
}

function Write-RotationJournal {
    param(
        [Parameter(Mandatory = $true)][string]$CurrentKeyId,
        [Parameter(Mandatory = $true)][string]$NextKeyId
    )

    if (Test-Path -LiteralPath $rotationPath) {
        throw "Credential rotation journal already exists."
    }
    $temporaryPath = "$rotationPath.create-$PID"
    $value = "{`"version`":1,`"currentKeyId`":`"$CurrentKeyId`",`"nextKeyId`":`"$NextKeyId`"}`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($value)
    try {
        $stream = [IO.FileStream]::new(
            $temporaryPath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        $fileInfo = [IO.FileInfo]::new($temporaryPath)
        $fileInfo.SetAccessControl((New-OperatorFileSecurity))
        Move-DurableFile -Source $temporaryPath -Destination $rotationPath
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Retire-Key {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$MarkerPath
    )

    Assert-ProtectedKey -Path $Path
    $zeros = [byte[]]::new(32)
    $stream = [IO.File]::Open(
        $Path,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $stream.Write($zeros, 0, $zeros.Length)
        $stream.SetLength($zeros.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
        [Array]::Clear($zeros, 0, $zeros.Length)
    }
    Move-DurableFile -Source $Path -Destination $MarkerPath -Replace
}

function Invoke-Maintenance {
    param([Parameter(Mandatory = $true)][string]$Operation)

    if (
        [string]::IsNullOrWhiteSpace($NodePath) -or
        [string]::IsNullOrWhiteSpace($MaintenanceEntryPoint)
    ) {
        throw "NodePath and MaintenanceEntryPoint are required for credential rotation recovery."
    }
    & $NodePath $MaintenanceEntryPoint $Operation $resolvedDataDirectory
    return $LASTEXITCODE
}

function Complete-RotationJournal {
    Move-DurableFile -Source $rotationPath -Destination $completedRotationPath -Replace
}

function Recover-Rotation {
    $journal = Read-RotationJournal
    $state = Invoke-Maintenance -Operation "classify-credential-key-rotation"
    $currentId = Get-OptionalKeyId -Path $canonicalKeyPath
    $nextId = Get-OptionalKeyId -Path $nextKeyPath
    $previousId = Get-OptionalKeyId -Path $previousKeyPath

    if ($state -eq 20) {
        if (
            $currentId -ne $journal.CurrentKeyId -or
            $null -ne $previousId -or
            (
                $null -ne $nextId -and
                $nextId -ne $journal.NextKeyId -and
                $nextId -ne $zeroKeyId
            )
        ) {
            throw "Credential rotation recovery found an invalid rollback state."
        }
        if ($nextId -eq $zeroKeyId) {
            Move-DurableFile -Source $nextKeyPath -Destination $abortedKeyPath -Replace
        }
        elseif ($null -ne $nextId) {
            Retire-Key -Path $nextKeyPath -MarkerPath $abortedKeyPath
        }
        Complete-RotationJournal
        return
    }
    if ($state -ne 21) {
        throw "Credential rotation journal does not match the gateway database."
    }

    $beforeSwap = (
        $currentId -eq $journal.CurrentKeyId -and
        $nextId -eq $journal.NextKeyId -and
        $null -eq $previousId
    )
    $betweenRenames = (
        $null -eq $currentId -and
        $nextId -eq $journal.NextKeyId -and
        $previousId -eq $journal.CurrentKeyId
    )
    $afterSwap = (
        $currentId -eq $journal.NextKeyId -and
        $null -eq $nextId -and
        $previousId -eq $journal.CurrentKeyId
    )
    $afterRetirement = (
        $currentId -eq $journal.NextKeyId -and
        $null -eq $nextId -and
        $null -eq $previousId
    )
    $retirementPending = (
        $currentId -eq $journal.NextKeyId -and
        $null -eq $nextId -and
        $previousId -eq $zeroKeyId
    )
    if (-not (
        $beforeSwap -or
        $betweenRenames -or
        $afterSwap -or
        $retirementPending -or
        $afterRetirement
    )) {
        throw "Credential rotation recovery found an invalid committed state."
    }
    if ($beforeSwap) {
        Move-DurableFile -Source $canonicalKeyPath -Destination $previousKeyPath
    }
    if ($beforeSwap -or $betweenRenames) {
        Move-DurableFile -Source $nextKeyPath -Destination $canonicalKeyPath
    }
    if ($retirementPending) {
        Move-DurableFile -Source $previousKeyPath -Destination $retiredKeyPath -Replace
    }
    elseif ($beforeSwap -or $betweenRenames -or $afterSwap) {
        Retire-Key -Path $previousKeyPath -MarkerPath $retiredKeyPath
    }
    Complete-RotationJournal
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

$env:COPILOT_IM_GATEWAY_WINDOWS_KEY_ACL = "operator-only-v1"
$recoveredExistingRotation = $false
if (Test-Path -LiteralPath $rotationPath) {
    Recover-Rotation
    $recoveredExistingRotation = $true
}
elseif ($RecoverRotation) {
    throw "Credential rotation journal is missing."
}

if ($Rotate -and -not $recoveredExistingRotation) {
    if (-not (Test-Path -LiteralPath $canonicalKeyPath)) {
        if ((Get-SqliteUserVersion -Path $databasePath) -ge 4) {
            throw "Credential master key is missing for an encrypted gateway database."
        }
        New-ProtectedKey -Path $canonicalKeyPath
    }
    Assert-ProtectedKey -Path $canonicalKeyPath
    if (-not (Test-Path -LiteralPath $nextKeyPath)) {
        New-ProtectedKey -Path $nextKeyPath
    }
    Assert-ProtectedKey -Path $nextKeyPath
    Write-RotationJournal `
        -CurrentKeyId (Get-KeyId -Path $canonicalKeyPath) `
        -NextKeyId (Get-KeyId -Path $nextKeyPath)
    if ((Invoke-Maintenance -Operation "reencrypt-credential-key") -ne 0) {
        throw "Credential database re-encryption failed safely."
    }
    Recover-Rotation
}
else {
    $keyPath = if ($ProvisionNext) { $nextKeyPath } else { $canonicalKeyPath }
    if (-not (Test-Path -LiteralPath $keyPath)) {
        if (-not $ProvisionNext -and (Get-SqliteUserVersion -Path $databasePath) -ge 4) {
            throw "Credential master key is missing for an encrypted gateway database."
        }
        New-ProtectedKey -Path $keyPath
    }
    Assert-ProtectedKey -Path $keyPath
}

if (-not [string]::IsNullOrWhiteSpace($NodePath) -and -not $Rotate -and -not $RecoverRotation) {
    if ([string]::IsNullOrWhiteSpace($EntryPoint)) {
        throw "EntryPoint is required when NodePath is provided."
    }
    & $NodePath $EntryPoint
    exit $LASTEXITCODE
}
