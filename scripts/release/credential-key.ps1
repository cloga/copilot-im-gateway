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
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

public static class GatewayDurableMove {
    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool MoveFileEx(
        string existingFileName,
        string newFileName,
        int flags
    );

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeleteFile(string fileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool FlushFileBuffers(IntPtr fileHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        IntPtr fileHandle,
        out ByHandleFileInformation information
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WriteFile(
        IntPtr fileHandle,
        byte[] buffer,
        uint bytesToWrite,
        out uint bytesWritten,
        IntPtr overlapped
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr objectHandle);

    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareAll = 0x00000007;
    private const uint OpenExisting = 3;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagWriteThrough = 0x80000000;

    private static IntPtr OpenFile(
        string path,
        uint access,
        uint share,
        uint flags
    ) {
        IntPtr handle = CreateFile(
            path,
            access,
            share,
            IntPtr.Zero,
            OpenExisting,
            flags,
            IntPtr.Zero
        );
        if (handle == new IntPtr(-1)) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return handle;
    }

    private static ByHandleFileInformation ReadInformation(IntPtr handle) {
        ByHandleFileInformation information;
        if (!GetFileInformationByHandle(handle, out information)) {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return information;
    }

    private static bool SameFile(
        ByHandleFileInformation left,
        ByHandleFileInformation right
    ) {
        return left.VolumeSerialNumber == right.VolumeSerialNumber &&
            left.FileIndexHigh == right.FileIndexHigh &&
            left.FileIndexLow == right.FileIndexLow;
    }

    public static bool IsSingleLinkRegularFile(string path) {
        IntPtr handle = OpenFile(
            path,
            GenericRead,
            FileShareAll,
            FileFlagOpenReparsePoint
        );
        try {
            ByHandleFileInformation information = ReadInformation(handle);
            return information.NumberOfLinks == 1 &&
                (information.FileAttributes & FileAttributeDirectory) == 0 &&
                (information.FileAttributes & FileAttributeReparsePoint) == 0;
        } finally {
            CloseHandle(handle);
        }
    }

    public static void SecureWipeRetirementMarker(
        string markerPath,
        string[] livePaths
    ) {
        IntPtr marker = OpenFile(
            markerPath,
            GenericRead | GenericWrite,
            0,
            FileFlagOpenReparsePoint | FileFlagWriteThrough
        );
        byte[] zeros = new byte[32];
        try {
            ByHandleFileInformation markerInformation = ReadInformation(marker);
            if (
                markerInformation.NumberOfLinks != 1 ||
                (markerInformation.FileAttributes & FileAttributeDirectory) != 0 ||
                (markerInformation.FileAttributes & FileAttributeReparsePoint) != 0
            ) {
                throw new InvalidOperationException(
                    "Retirement marker is not an isolated regular file."
                );
            }
            foreach (string livePath in livePaths) {
                if (!File.Exists(livePath)) {
                    continue;
                }
                IntPtr live = OpenFile(
                    livePath,
                    GenericRead,
                    FileShareAll,
                    FileFlagOpenReparsePoint
                );
                try {
                    if (SameFile(markerInformation, ReadInformation(live))) {
                        throw new InvalidOperationException(
                            "Retirement marker aliases a live credential key."
                        );
                    }
                } finally {
                    CloseHandle(live);
                }
            }
            uint written;
            if (
                !WriteFile(marker, zeros, (uint)zeros.Length, out written, IntPtr.Zero) ||
                written != (uint)zeros.Length
            ) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            if (!FlushFileBuffers(marker)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        } finally {
            Array.Clear(zeros, 0, zeros.Length);
            CloseHandle(marker);
        }
    }

    public static bool FlushDirectory(string directoryPath) {
        IntPtr handle = CreateFile(
            directoryPath,
            GenericWrite,
            FileShareAll,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagWriteThrough,
            IntPtr.Zero
        );
        if (handle == new IntPtr(-1)) {
            return false;
        }
        try {
            return FlushFileBuffers(handle);
        } finally {
            CloseHandle(handle);
        }
    }
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

function Remove-DurableFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-OperatorOnlyAcl -Path $Path -Directory $false
    $deleted = $false
    $errorCode = 0
    foreach ($attempt in 1..3) {
        if ([GatewayDurableMove]::DeleteFile($Path)) {
            $deleted = $true
            break
        }
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        Start-Sleep -Milliseconds 20
    }
    if (-not $deleted) {
        throw "Credential rotation marker could not be deleted (Windows error $errorCode)."
    }
    if (-not [GatewayDurableMove]::FlushDirectory($resolvedDataDirectory)) {
        $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "Credential rotation marker deletion could not be durably flushed (Windows error $errorCode)."
    }
    if (Test-Path -LiteralPath $Path) {
        throw "Credential rotation marker deletion could not be verified."
    }
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
    if (-not [GatewayDurableMove]::IsSingleLinkRegularFile($Path)) {
        throw "Credential master key must be one isolated regular file."
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
    $legacyPattern = '^\{"version":1,"currentKeyId":"([a-f0-9]{64})","nextKeyId":"([a-f0-9]{64})"\}\r?\n$'
    if ($raw -match $legacyPattern -and $Matches[1] -ne $Matches[2]) {
        return @{
            Version = 1
            CurrentKeyId = $Matches[1]
            NextKeyId = $Matches[2]
        }
    }
    $currentPattern = '^\{"version":2,"currentKeyId":"([a-f0-9]{64})","nextKeyId":"([a-f0-9]{64})","retirementMarker":"(credential-master-key\.(retire|abort)-([a-f0-9]{64}))","retirementKeyId":"([a-f0-9]{64})","retirementState":"(prepared|wiping|rollback-wiping)"\}\r?\n$'
    if ($raw -notmatch $currentPattern) {
        throw "Credential rotation journal is invalid."
    }
    $currentKeyId = $Matches[1]
    $nextKeyId = $Matches[2]
    $retirementMarker = $Matches[3]
    $markerKind = $Matches[4]
    $markerKeyId = $Matches[5]
    $retirementKeyId = $Matches[6]
    $retirementState = $Matches[7]
    $expectedRetirementKeyId = if ($retirementState -eq "rollback-wiping") {
        $nextKeyId
    } else {
        $currentKeyId
    }
    $expectedMarkerKind = if ($retirementState -eq "rollback-wiping") {
        "abort"
    } else {
        "retire"
    }
    if (
        $currentKeyId -eq $nextKeyId -or
        $markerKind -ne $expectedMarkerKind -or
        $markerKeyId -ne $expectedRetirementKeyId -or
        $retirementKeyId -ne $expectedRetirementKeyId
    ) {
        throw "Credential rotation journal is invalid."
    }
    return @{
        Version = 2
        CurrentKeyId = $currentKeyId
        NextKeyId = $nextKeyId
        RetirementMarker = $retirementMarker
        RetirementKeyId = $retirementKeyId
        RetirementState = $retirementState
    }
}

function Write-RotationJournal {
    param(
        [Parameter(Mandatory = $true)][string]$CurrentKeyId,
        [Parameter(Mandatory = $true)][string]$NextKeyId,
        [ValidateSet("prepared", "wiping", "rollback-wiping")]
        [string]$RetirementState = "prepared",
        [string]$RetirementKeyId,
        [ValidateSet("retire", "abort")][string]$RetirementMarkerKind = "retire",
        [switch]$Replace
    )

    if (-not $Replace -and (Test-Path -LiteralPath $rotationPath)) {
        throw "Credential rotation journal already exists."
    }
    $temporaryPath = "$rotationPath.create-$PID"
    if ([string]::IsNullOrWhiteSpace($RetirementKeyId)) {
        $RetirementKeyId = $CurrentKeyId
    }
    $retirementMarker = "credential-master-key.$RetirementMarkerKind-$RetirementKeyId"
    $value = "{`"version`":2,`"currentKeyId`":`"$CurrentKeyId`",`"nextKeyId`":`"$NextKeyId`",`"retirementMarker`":`"$retirementMarker`",`"retirementKeyId`":`"$RetirementKeyId`",`"retirementState`":`"$RetirementState`"}`n"
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
        Move-DurableFile `
            -Source $temporaryPath `
            -Destination $rotationPath `
            -Replace:$Replace
    }
    finally {
        [Array]::Clear($bytes, 0, $bytes.Length)
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Move-ToRetirementMarker {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][string]$ExpectedKeyId
    )

    if ((Get-KeyId -Path $Path) -ne $ExpectedKeyId) {
        throw "Credential rotation key does not match its journal identity."
    }
    if (Test-Path -LiteralPath $MarkerPath) {
        throw "Credential rotation retirement marker already exists."
    }
    Move-DurableFile -Source $Path -Destination $MarkerPath
    if ((Get-KeyId -Path $MarkerPath) -ne $ExpectedKeyId) {
        throw "Credential rotation retirement marker identity changed."
    }
}

function Assert-RetirementMarker {
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][string]$ExpectedKeyId,
        [switch]$AllowPartialWipe
    )

    Assert-ProtectedKey -Path $MarkerPath
    if (-not $AllowPartialWipe -and (Get-KeyId -Path $MarkerPath) -ne $ExpectedKeyId) {
        throw "Credential rotation retirement marker identity is invalid."
    }
}

function Wipe-RetirementMarker {
    param([Parameter(Mandatory = $true)][string]$MarkerPath)

    Assert-ProtectedKey -Path $MarkerPath
    if (
        $env:NODE_ENV -eq "test" -and
        $env:COPILOT_IM_GATEWAY_TEST_TORN_RETIREMENT_WIPE -eq "1"
    ) {
        $stream = [IO.FileStream]::new(
            $MarkerPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::WriteThrough
        )
        try {
            $stream.Write([byte[]]::new(11), 0, 11)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        throw "Injected torn retirement marker wipe."
    }
    [GatewayDurableMove]::SecureWipeRetirementMarker(
        $MarkerPath,
        [string[]]@(
            $canonicalKeyPath,
            $nextKeyPath,
            $previousKeyPath
        )
    )
}

function Get-LegacyRetirementPath {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$KeyId
    )

    return Join-Path $resolvedDataDirectory "credential-master-key.$Kind-$KeyId"
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

function Complete-RetirementCleanup {
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][string]$ExpectedKeyId
    )

    if (Test-Path -LiteralPath $MarkerPath) {
        Assert-RetirementMarker `
            -MarkerPath $MarkerPath `
            -ExpectedKeyId $ExpectedKeyId `
            -AllowPartialWipe
        if (
            $env:NODE_ENV -eq "test" -and
            $env:COPILOT_IM_GATEWAY_TEST_DEFER_RETIREMENT_CLEANUP -eq "1"
        ) {
            return $false
        }
        try {
            Wipe-RetirementMarker -MarkerPath $MarkerPath
        }
        catch {
            Write-Warning "Credential retirement marker wipe was deferred."
            return $false
        }
        try {
            Remove-DurableFile -Path $MarkerPath
        }
        catch {
            Write-Warning "Credential retirement marker cleanup was deferred: $($_.Exception.Message)"
            return $false
        }
    }
    elseif (-not [GatewayDurableMove]::FlushDirectory($resolvedDataDirectory)) {
        return $false
    }
    Complete-RotationJournal
    return $true
}

function Recover-VersionTwoRotation {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Journal,
        [Parameter(Mandatory = $true)][int]$DatabaseState
    )

    if (Test-Path -LiteralPath $previousKeyPath) {
        throw "Credential rotation found an unexpected legacy key path."
    }
    $markerPath = Join-Path $resolvedDataDirectory $Journal.RetirementMarker
    if (
        [IO.Path]::GetDirectoryName($markerPath) -ne $resolvedDataDirectory -or
        [IO.Path]::GetFileName($markerPath) -ne $Journal.RetirementMarker
    ) {
        throw "Credential rotation retirement marker path is invalid."
    }
    $currentId = Get-OptionalKeyId -Path $canonicalKeyPath
    $nextId = Get-OptionalKeyId -Path $nextKeyPath
    $markerExists = Test-Path -LiteralPath $markerPath
    $preparedAbortPath = Join-Path `
        $resolvedDataDirectory `
        "credential-master-key.abort-$($Journal.NextKeyId)"
    $preparedAbortId = if (
        $Journal.RetirementState -eq "prepared" -and
        (Test-Path -LiteralPath $preparedAbortPath)
    ) {
        Get-KeyId -Path $preparedAbortPath
    } else { $null }

    if ($Journal.RetirementState -eq "rollback-wiping") {
        if (
            $DatabaseState -ne 20 -or
            $currentId -ne $Journal.CurrentKeyId -or
            $null -ne $nextId
        ) {
            throw "Credential rotation recovery found an invalid rollback wiping state."
        }
        if ($markerExists) {
            Assert-RetirementMarker `
                -MarkerPath $markerPath `
                -ExpectedKeyId $Journal.RetirementKeyId `
                -AllowPartialWipe
        }
        [void](Complete-RetirementCleanup `
            -MarkerPath $markerPath `
            -ExpectedKeyId $Journal.RetirementKeyId)
        return
    }
    if ($DatabaseState -eq 20) {
        if (
            $Journal.RetirementState -ne "prepared" -or
            $currentId -ne $Journal.CurrentKeyId -or
            $markerExists -or
            ($null -ne $nextId -and $nextId -ne $Journal.NextKeyId) -or
            (
                $null -ne $preparedAbortId -and
                $preparedAbortId -ne $Journal.NextKeyId
            ) -or
            (
                $null -ne $nextId -and
                $null -ne $preparedAbortId
            )
        ) {
            throw "Credential rotation recovery found an invalid rollback state."
        }
        if ($null -ne $nextId) {
            Move-ToRetirementMarker `
                -Path $nextKeyPath `
                -MarkerPath $preparedAbortPath `
                -ExpectedKeyId $Journal.NextKeyId
        }
        if ($null -ne $nextId -or $null -ne $preparedAbortId) {
            Write-RotationJournal `
                -CurrentKeyId $Journal.CurrentKeyId `
                -NextKeyId $Journal.NextKeyId `
                -RetirementState "rollback-wiping" `
                -RetirementKeyId $Journal.NextKeyId `
                -RetirementMarkerKind "abort" `
                -Replace
            [void](Complete-RetirementCleanup `
                -MarkerPath $preparedAbortPath `
                -ExpectedKeyId $Journal.NextKeyId)
            return
        }
        Complete-RotationJournal
        return
    }
    if ($DatabaseState -ne 21) {
        throw "Credential rotation journal does not match the gateway database."
    }
    if ($null -ne $preparedAbortId) {
        throw "Credential rotation found an unexpected rollback marker."
    }
    if ($Journal.RetirementState -eq "wiping") {
        if (
            $currentId -ne $Journal.NextKeyId -or
            $null -ne $nextId
        ) {
            throw "Credential rotation recovery found an invalid wiping state."
        }
        if ($markerExists) {
            Assert-RetirementMarker `
                -MarkerPath $markerPath `
                -ExpectedKeyId $Journal.RetirementKeyId `
                -AllowPartialWipe
        }
        [void](Complete-RetirementCleanup `
            -MarkerPath $markerPath `
            -ExpectedKeyId $Journal.RetirementKeyId)
        return
    }

    $markerId = if ($markerExists) {
        Assert-RetirementMarker `
            -MarkerPath $markerPath `
            -ExpectedKeyId $Journal.RetirementKeyId
        $Journal.RetirementKeyId
    } else { $null }
    $beforeRetirementMove = (
        $currentId -eq $Journal.CurrentKeyId -and
        $nextId -eq $Journal.NextKeyId -and
        $null -eq $markerId
    )
    $betweenRenames = (
        $null -eq $currentId -and
        $nextId -eq $Journal.NextKeyId -and
        $markerId -eq $Journal.RetirementKeyId
    )
    $afterSwap = (
        $currentId -eq $Journal.NextKeyId -and
        $null -eq $nextId -and
        $markerId -eq $Journal.RetirementKeyId
    )
    if (-not ($beforeRetirementMove -or $betweenRenames -or $afterSwap)) {
        throw "Credential rotation recovery found an invalid committed state."
    }
    if ($beforeRetirementMove) {
        Move-ToRetirementMarker `
            -Path $canonicalKeyPath `
            -MarkerPath $markerPath `
            -ExpectedKeyId $Journal.RetirementKeyId
    }
    if ($beforeRetirementMove -or $betweenRenames) {
        Move-DurableFile -Source $nextKeyPath -Destination $canonicalKeyPath
    }
    Write-RotationJournal `
        -CurrentKeyId $Journal.CurrentKeyId `
        -NextKeyId $Journal.NextKeyId `
        -RetirementState "wiping" `
        -Replace
    [void](Complete-RetirementCleanup `
        -MarkerPath $markerPath `
        -ExpectedKeyId $Journal.RetirementKeyId)
}

function Recover-LegacyRotation {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Journal,
        [Parameter(Mandatory = $true)][int]$DatabaseState
    )

    $currentId = Get-OptionalKeyId -Path $canonicalKeyPath
    $nextId = Get-OptionalKeyId -Path $nextKeyPath
    $previousId = Get-OptionalKeyId -Path $previousKeyPath
    $legacyMarker = Get-LegacyRetirementPath `
        -Kind "retire" `
        -KeyId $Journal.CurrentKeyId
    $legacyMarkerId = Get-OptionalKeyId -Path $legacyMarker
    $legacyAbortMarker = Get-LegacyRetirementPath `
        -Kind "abort" `
        -KeyId $Journal.NextKeyId
    $legacyAbortMarkerId = Get-OptionalKeyId -Path $legacyAbortMarker

    if ($DatabaseState -eq 20) {
        if (
            $currentId -ne $journal.CurrentKeyId -or
            $null -ne $previousId -or
            $null -ne $legacyMarkerId -or
            (
                $null -ne $nextId -and
                $null -ne $legacyAbortMarkerId
            )
        ) {
            throw "Credential rotation recovery found an invalid rollback state."
        }
        if (
            $null -ne $nextId -and
            $nextId -ne $Journal.NextKeyId
        ) {
            Move-DurableFile `
                -Source $nextKeyPath `
                -Destination $legacyAbortMarker
        }
        elseif ($null -ne $nextId) {
            Move-ToRetirementMarker `
                -Path $nextKeyPath `
                -MarkerPath $legacyAbortMarker `
                -ExpectedKeyId $Journal.NextKeyId
        }
        if (
            $null -ne $nextId -or
            $null -ne $legacyAbortMarkerId
        ) {
            Write-RotationJournal `
                -CurrentKeyId $Journal.CurrentKeyId `
                -NextKeyId $Journal.NextKeyId `
                -RetirementState "rollback-wiping" `
                -RetirementKeyId $Journal.NextKeyId `
                -RetirementMarkerKind "abort" `
                -Replace
            [void](Complete-RetirementCleanup `
                -MarkerPath $legacyAbortMarker `
                -ExpectedKeyId $Journal.NextKeyId)
            return
        }
        Complete-RotationJournal
        return
    }
    if ($DatabaseState -ne 21) {
        throw "Credential rotation journal does not match the gateway database."
    }

    $beforeSwap = (
        $currentId -eq $journal.CurrentKeyId -and
        $nextId -eq $journal.NextKeyId -and
        $null -eq $previousId -and
        $null -eq $legacyMarkerId
    )
    $betweenRenamesPrevious = (
        $null -eq $currentId -and
        $nextId -eq $journal.NextKeyId -and
        $previousId -eq $journal.CurrentKeyId -and
        $null -eq $legacyMarkerId
    )
    $betweenRenamesMarker = (
        $null -eq $currentId -and
        $nextId -eq $journal.NextKeyId -and
        $null -eq $previousId -and
        $legacyMarkerId -eq $journal.CurrentKeyId
    )
    $afterSwapPrevious = (
        $currentId -eq $journal.NextKeyId -and
        $null -eq $nextId -and
        $previousId -eq $journal.CurrentKeyId -and
        $null -eq $legacyMarkerId
    )
    $afterSwapMarker = (
        $currentId -eq $journal.NextKeyId -and
        $null -eq $nextId -and
        $null -eq $previousId -and
        $legacyMarkerId -eq $journal.CurrentKeyId
    )
    $afterSwapPartialMarker = (
        $currentId -eq $journal.NextKeyId -and
        $null -eq $nextId -and
        $null -eq $previousId -and
        $null -ne $legacyMarkerId -and
        $legacyMarkerId -ne $journal.CurrentKeyId
    )
    $afterRetirement = (
        $currentId -eq $journal.NextKeyId -and
        $null -eq $nextId -and
        $null -eq $previousId -and
        $null -eq $legacyMarkerId
    )
    $retirementPending = (
        $currentId -eq $journal.NextKeyId -and
        $null -eq $nextId -and
        $previousId -eq $zeroKeyId -and
        $null -eq $legacyMarkerId
    )
    $retirementPartial = (
        $currentId -eq $journal.NextKeyId -and
        $null -eq $nextId -and
        $null -ne $previousId -and
        $previousId -ne $journal.CurrentKeyId -and
        $previousId -ne $zeroKeyId -and
        $null -eq $legacyMarkerId
    )
    if (-not (
        $beforeSwap -or
        $betweenRenamesPrevious -or
        $betweenRenamesMarker -or
        $afterSwapPrevious -or
        $afterSwapMarker -or
        $afterSwapPartialMarker -or
        $retirementPending -or
        $retirementPartial -or
        $afterRetirement
    )) {
        throw "Credential rotation recovery found an invalid committed state."
    }
    if ($beforeSwap) {
        Move-ToRetirementMarker `
            -Path $canonicalKeyPath `
            -MarkerPath $legacyMarker `
            -ExpectedKeyId $Journal.CurrentKeyId
    }
    if ($betweenRenamesPrevious) {
        Move-ToRetirementMarker `
            -Path $previousKeyPath `
            -MarkerPath $legacyMarker `
            -ExpectedKeyId $Journal.CurrentKeyId
    }
    if (
        $beforeSwap -or
        $betweenRenamesPrevious -or
        $betweenRenamesMarker
    ) {
        Move-DurableFile -Source $nextKeyPath -Destination $canonicalKeyPath
    }
    if ($retirementPending -or $retirementPartial) {
        Move-DurableFile `
            -Source $previousKeyPath `
            -Destination $legacyMarker
    }
    elseif ($afterSwapPrevious) {
        Move-ToRetirementMarker `
            -Path $previousKeyPath `
            -MarkerPath $legacyMarker `
            -ExpectedKeyId $Journal.CurrentKeyId
    }
    if (
        $beforeSwap -or
        $betweenRenamesPrevious -or
        $betweenRenamesMarker -or
        $afterSwapPrevious -or
        $afterSwapMarker -or
        $afterSwapPartialMarker -or
        $retirementPending -or
        $retirementPartial
    ) {
        Write-RotationJournal `
            -CurrentKeyId $Journal.CurrentKeyId `
            -NextKeyId $Journal.NextKeyId `
            -RetirementState "wiping" `
            -Replace
        [void](Complete-RetirementCleanup `
            -MarkerPath $legacyMarker `
            -ExpectedKeyId $Journal.CurrentKeyId)
        return
    }
    Complete-RotationJournal
}

function Recover-Rotation {
    $journal = Read-RotationJournal
    $state = Invoke-Maintenance -Operation "classify-credential-key-rotation"
    if ($journal.Version -eq 2) {
        Recover-VersionTwoRotation -Journal $journal -DatabaseState $state
    }
    else {
        Recover-LegacyRotation -Journal $journal -DatabaseState $state
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
