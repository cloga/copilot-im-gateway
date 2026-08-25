param(
    [Parameter(Mandatory = $true)][string]$InstallDirectory,
    [string]$DataDirectory,
    [string]$TokenFile,
    [int]$Port = -1,
    [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($null -eq ("GatewayCommandLine.Parser" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace GatewayCommandLine
{
    public static class Parser
    {
        [DllImport("shell32.dll", SetLastError = true)]
        private static extern IntPtr CommandLineToArgvW(
            [MarshalAs(UnmanagedType.LPWStr)] string commandLine,
            out int argumentCount);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static string[] Split(string commandLine)
        {
            int argumentCount;
            IntPtr arguments = CommandLineToArgvW(commandLine, out argumentCount);
            if (arguments == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                string[] result = new string[argumentCount];
                for (int index = 0; index < argumentCount; index++)
                {
                    IntPtr argument = Marshal.ReadIntPtr(arguments, index * IntPtr.Size);
                    result[index] = Marshal.PtrToStringUni(argument);
                }
                return result;
            }
            finally
            {
                LocalFree(arguments);
            }
        }
    }
}
'@
}

function ConvertFrom-WindowsCommandLine {
    param([Parameter(Mandatory = $true)][string]$CommandLine)

    return [GatewayCommandLine.Parser]::Split($CommandLine)
}

function Test-NodeProcessExecutable {
    param([Parameter(Mandatory = $true)][object]$Process)

    $name = [string]$Process.Name
    $executablePath = [string]$Process.ExecutablePath
    if (
        [string]::IsNullOrWhiteSpace($name) -or
        [string]::IsNullOrWhiteSpace($executablePath) -or
        -not [IO.Path]::IsPathRooted($executablePath)
    ) {
        return $false
    }

    $nodeNames = @("node", "node.exe")
    return (
        $nodeNames -contains $name.ToLowerInvariant() -and
        $nodeNames -contains ([IO.Path]::GetFileName($executablePath)).ToLowerInvariant()
    )
}

function Test-GatewayCommandLine {
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][string[]]$Entrypoints
    )

    try {
        $arguments = @(ConvertFrom-WindowsCommandLine -CommandLine $CommandLine)
    }
    catch {
        return $false
    }
    if ($arguments.Count -lt 2) {
        return $false
    }

    $scriptArgument = [string]$arguments[1]
    if (-not [IO.Path]::IsPathRooted($scriptArgument)) {
        return $false
    }
    try {
        $normalizedScript = [IO.Path]::GetFullPath($scriptArgument)
    }
    catch {
        return $false
    }
    foreach ($entrypoint in $Entrypoints) {
        if ([StringComparer]::OrdinalIgnoreCase.Equals($normalizedScript, $entrypoint)) {
            return $true
        }
    }
    return $false
}

function Test-GatewayProcess {
    param(
        [Parameter(Mandatory = $true)][object]$Process,
        [Parameter(Mandatory = $true)][string[]]$Entrypoints
    )

    $commandLine = [string]$Process.CommandLine
    if ([string]::IsNullOrWhiteSpace($commandLine)) {
        return $false
    }
    return (
        (Test-NodeProcessExecutable -Process $Process) -and
        (Test-GatewayCommandLine -CommandLine $commandLine -Entrypoints $Entrypoints)
    )
}

function Test-InstalledGatewayProcess {
    param([Parameter(Mandatory = $true)][string[]]$Entrypoints)

    return $null -ne (
        Get-CimInstance Win32_Process |
            Where-Object {
                Test-GatewayProcess -Process $_ -Entrypoints $Entrypoints
            } |
            Select-Object -First 1
    )
}

function Invoke-AuthenticatedGatewayShutdown {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$BearerToken
    )

    try {
        $response = Invoke-WebRequest `
            -Uri "http://127.0.0.1:$Port/v2/admin/shutdown" `
            -Method Post `
            -Headers @{ Authorization = "Bearer $BearerToken" } `
            -TimeoutSec 5 `
            -UseBasicParsing
        return [int]$response.StatusCode -eq 202
    }
    catch {
        return $false
    }
}

function Get-HmacSha256Hex {
    param(
        [Parameter(Mandatory = $true)][string]$BearerToken,
        [Parameter(Mandatory = $true)][string]$Purpose,
        [Parameter(Mandatory = $true)][string]$Challenge
    )

    $hmac = [Security.Cryptography.HMACSHA256]::new(
        [Text.Encoding]::UTF8.GetBytes($BearerToken)
    )
    try {
        $payload = [Text.Encoding]::UTF8.GetBytes(
            $Purpose + [char]0 + $Challenge
        )
        return (
            [BitConverter]::ToString($hmac.ComputeHash($payload))
        ).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $hmac.Dispose()
    }
}

function Test-AuthenticatedGatewayIdentity {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$BearerToken
    )

    $challengeBytes = New-Object byte[] 32
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($challengeBytes)
    }
    finally {
        $random.Dispose()
    }
    $challenge = (
        [BitConverter]::ToString($challengeBytes)
    ).Replace("-", "").ToLowerInvariant()
    $requestProof = Get-HmacSha256Hex `
        -BearerToken $BearerToken `
        -Purpose "request" `
        -Challenge $challenge
    $expectedResponseProof = Get-HmacSha256Hex `
        -BearerToken $BearerToken `
        -Purpose "response" `
        -Challenge $challenge

    try {
        $response = Invoke-WebRequest `
            -Uri "http://127.0.0.1:$Port/v2/admin/identity" `
            -Method Get `
            -Headers @{
                "X-Gateway-Shutdown-Challenge" = $challenge
                "X-Gateway-Shutdown-Proof" = $requestProof
            } `
            -TimeoutSec 5 `
            -UseBasicParsing
        if ([int]$response.StatusCode -ne 200) {
            return $false
        }
        $identity = $response.Content | ConvertFrom-Json
        return (
            [int]$identity.apiVersion -eq 2 -and
            $null -ne $identity.capabilities -and
            @($identity.capabilities) -contains "reservation-ownership" -and
            [string]$identity.proof -ceq $expectedResponseProof
        )
    }
    catch {
        return $false
    }
}

function Test-LoopbackPortAvailable {
    param([Parameter(Mandatory = $true)][int]$Port)

    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
        return $true
    }
    catch {
        return $false
    }
    finally {
        $listener.Stop()
    }
}

function Get-ManualExitMessage {
    param([Parameter(Mandatory = $true)][string]$Reason)

    return "$Reason Exit the old Copilot IM Gateway and retry."
}

function Invoke-StopGatewayDaemon {
    param(
        [Parameter(Mandatory = $true)][string]$InstallDirectory,
        [string]$DataDirectory,
        [string]$TokenFile,
        [int]$Port = -1,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
    )

    $resolvedInstallDirectory = [IO.Path]::GetFullPath($InstallDirectory)
    $entrypoints = @(
        [IO.Path]::GetFullPath((Join-Path $resolvedInstallDirectory "dist\daemon\main.js")),
        [IO.Path]::GetFullPath((Join-Path $resolvedInstallDirectory "app\dist\daemon\main.js"))
    )

    if ([string]::IsNullOrWhiteSpace($DataDirectory)) {
        $DataDirectory = $env:COPILOT_IM_GATEWAY_DATA_DIR
    }
    if ([string]::IsNullOrWhiteSpace($DataDirectory)) {
        $DataDirectory = Join-Path `
            ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)) `
            ".copilot-im-gateway"
    }
    $resolvedDataDirectory = [IO.Path]::GetFullPath($DataDirectory)

    if ([string]::IsNullOrWhiteSpace($TokenFile)) {
        $TokenFile = $env:COPILOT_IM_GATEWAY_TOKEN_FILE
    }
    if ([string]::IsNullOrWhiteSpace($TokenFile)) {
        $TokenFile = Join-Path $resolvedDataDirectory "auth-token"
    }
    $resolvedTokenFile = [IO.Path]::GetFullPath($TokenFile)

    if ($Port -eq -1) {
        $portText = $env:COPILOT_IM_GATEWAY_PORT
        if ([string]::IsNullOrWhiteSpace($portText)) {
            $Port = 32147
        }
        elseif (
            -not [int]::TryParse($portText, [ref]$Port) -or
            $Port -lt 0 -or
            $Port -gt 65535
        ) {
            throw "COPILOT_IM_GATEWAY_PORT must be an integer from 0 to 65535."
        }
    }
    elseif ($Port -lt 0 -or $Port -gt 65535) {
        throw "Port must be an integer from 0 to 65535."
    }

    try {
        $gatewayDetected = Test-InstalledGatewayProcess -Entrypoints $entrypoints
    }
    catch {
        throw (Get-ManualExitMessage `
            -Reason "The upgrade guard could not inspect running gateway processes.")
    }

    if ($Port -eq 0) {
        if ($gatewayDetected) {
            throw (Get-ManualExitMessage `
                -Reason "A gateway process is running on an automatically assigned port.")
        }
        return
    }

    if (Test-LoopbackPortAvailable -Port $Port) {
        if ($gatewayDetected) {
            throw (Get-ManualExitMessage `
                -Reason "A gateway process is running outside the configured loopback port.")
        }
        return
    }

    if (-not (Test-Path -LiteralPath $resolvedTokenFile -PathType Leaf)) {
        throw (Get-ManualExitMessage `
            -Reason "The gateway token file was not found, so authenticated v2 shutdown is unavailable.")
    }
    try {
        $bearerToken = (Get-Content -LiteralPath $resolvedTokenFile -Raw).Trim()
    }
    catch {
        throw (Get-ManualExitMessage `
            -Reason "The gateway token file could not be read, so authenticated v2 shutdown is unavailable.")
    }
    if ($bearerToken.Length -lt 32) {
        throw (Get-ManualExitMessage `
            -Reason "The gateway token file is invalid, so authenticated v2 shutdown is unavailable.")
    }

    if (-not $gatewayDetected) {
        throw (Get-ManualExitMessage `
            -Reason "The listener on 127.0.0.1:$Port is not an exact installed gateway process.")
    }
    try {
        $gatewayDetected = Test-InstalledGatewayProcess -Entrypoints $entrypoints
    }
    catch {
        throw (Get-ManualExitMessage `
            -Reason "The upgrade guard could not revalidate the installed gateway process.")
    }
    if (
        -not $gatewayDetected -or
        -not (Test-AuthenticatedGatewayIdentity `
            -Port $Port `
            -BearerToken $bearerToken)
    ) {
        throw (Get-ManualExitMessage `
            -Reason "The listener on 127.0.0.1:$Port did not prove authenticated v2 gateway identity.")
    }

    if (-not (Invoke-AuthenticatedGatewayShutdown `
        -Port $Port `
        -BearerToken $bearerToken)) {
        throw (Get-ManualExitMessage `
            -Reason "The listener on 127.0.0.1:$Port did not accept authenticated v2 shutdown.")
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ($true) {
        try {
            $gatewayDetected = Test-InstalledGatewayProcess -Entrypoints $entrypoints
        }
        catch {
            throw (Get-ManualExitMessage `
                -Reason "The upgrade guard could not confirm gateway process exit.")
        }
        if (
            (Test-LoopbackPortAvailable -Port $Port) -and
            -not $gatewayDetected
        ) {
            return
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            throw (Get-ManualExitMessage `
                -Reason "Authenticated v2 shutdown did not release the gateway process and loopback port.")
        }
        Start-Sleep -Milliseconds 100
    }
}

if ($MyInvocation.InvocationName -ne ".") {
    Invoke-StopGatewayDaemon @PSBoundParameters
}
