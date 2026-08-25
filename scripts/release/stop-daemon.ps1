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

function Get-GatewayCommandLineEntrypoint {
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][string[]]$Entrypoints
    )

    try {
        $arguments = @(ConvertFrom-WindowsCommandLine -CommandLine $CommandLine)
    }
    catch {
        return $null
    }
    if ($arguments.Count -lt 2) {
        return $null
    }

    $scriptArgument = [string]$arguments[1]
    if (-not [IO.Path]::IsPathRooted($scriptArgument)) {
        return $null
    }
    try {
        $normalizedScript = [IO.Path]::GetFullPath($scriptArgument)
    }
    catch {
        return $null
    }
    foreach ($entrypoint in $Entrypoints) {
        if ([StringComparer]::OrdinalIgnoreCase.Equals($normalizedScript, $entrypoint)) {
            return $entrypoint
        }
    }
    return $null
}

function Test-GatewayCommandLine {
    param(
        [Parameter(Mandatory = $true)][string]$CommandLine,
        [Parameter(Mandatory = $true)][string[]]$Entrypoints
    )

    return $null -ne (
        Get-GatewayCommandLineEntrypoint `
            -CommandLine $CommandLine `
            -Entrypoints $Entrypoints
    )
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
        $null -ne (
            Get-GatewayCommandLineEntrypoint `
                -CommandLine $commandLine `
                -Entrypoints $Entrypoints
        )
    )
}

function ConvertTo-ProcessCreationMarker {
    param([Parameter(Mandatory = $true)][object]$Process)

    $creationDate = $Process.CreationDate
    if ($null -eq $creationDate) {
        throw "The listener process creation time is unavailable."
    }
    if ($creationDate -isnot [DateTime]) {
        try {
            $creationDate = [Management.ManagementDateTimeConverter]::ToDateTime(
                [string]$creationDate
            )
        }
        catch {
            throw "The listener process creation time is invalid."
        }
    }
    return (
        ([DateTime]$creationDate).ToUniversalTime().ToFileTimeUtc().ToString(
            [Globalization.CultureInfo]::InvariantCulture
        )
    )
}

function ConvertTo-GatewayProcessRecord {
    param(
        [Parameter(Mandatory = $true)][object]$Process,
        [Parameter(Mandatory = $true)][string[]]$Entrypoints
    )

    if (-not (Test-GatewayProcess -Process $Process -Entrypoints $Entrypoints)) {
        return $null
    }
    $entrypoint = Get-GatewayCommandLineEntrypoint `
        -CommandLine ([string]$Process.CommandLine) `
        -Entrypoints $Entrypoints
    if ($null -eq $entrypoint) {
        return $null
    }
    $processId = [long]$Process.ProcessId
    if ($processId -lt 1 -or $processId -gt [uint32]::MaxValue) {
        throw "The listener process ID is invalid."
    }
    return [pscustomobject]@{
        ProcessId = $processId
        CreationMarker = ConvertTo-ProcessCreationMarker -Process $Process
        ExecutablePath = [IO.Path]::GetFullPath([string]$Process.ExecutablePath)
        Entrypoint = [IO.Path]::GetFullPath([string]$entrypoint)
    }
}

function Test-GatewayProcessRecord {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][object]$Actual
    )

    return (
        [long]$Expected.ProcessId -eq [long]$Actual.ProcessId -and
        [string]$Expected.CreationMarker -ceq [string]$Actual.CreationMarker -and
        [StringComparer]::OrdinalIgnoreCase.Equals(
            [string]$Expected.ExecutablePath,
            [string]$Actual.ExecutablePath
        ) -and
        [StringComparer]::OrdinalIgnoreCase.Equals(
            [string]$Expected.Entrypoint,
            [string]$Actual.Entrypoint
        )
    )
}

function Get-InstalledGatewayProcessRecords {
    param([Parameter(Mandatory = $true)][string[]]$Entrypoints)

    $records = @()
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        if (Test-GatewayProcess -Process $process -Entrypoints $Entrypoints) {
            $records += ConvertTo-GatewayProcessRecord `
                -Process $process `
                -Entrypoints $Entrypoints
        }
    }
    return @($records)
}

function Get-ValidatedGatewayListenerOwner {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string[]]$Entrypoints
    )

    if (
        $null -eq (
            Get-Command Get-NetTCPConnection `
                -ErrorAction SilentlyContinue
        )
    ) {
        throw "Get-NetTCPConnection is unavailable."
    }
    $listeners = @(
        Get-NetTCPConnection `
            -State Listen `
            -LocalAddress "127.0.0.1" `
            -LocalPort $Port `
            -ErrorAction Stop |
            Where-Object {
                [string]$_.LocalAddress -ceq "127.0.0.1" -and
                [int]$_.LocalPort -eq $Port -and
                [string]$_.State -ieq "Listen"
            }
    )
    if ($listeners.Count -ne 1) {
        throw "Expected one exact IPv4 loopback Listen socket, found $($listeners.Count)."
    }
    $owningProcessId = [long]$listeners[0].OwningProcess
    if ($owningProcessId -lt 1 -or $owningProcessId -gt [uint32]::MaxValue) {
        throw "The exact IPv4 loopback listener has an invalid owning process ID."
    }
    $ownerProcesses = @(
        Get-CimInstance Win32_Process `
            -Filter "ProcessId = $owningProcessId" `
            -ErrorAction Stop
    )
    if ($ownerProcesses.Count -ne 1) {
        throw "The exact IPv4 loopback listener process could not be resolved uniquely."
    }
    $owner = ConvertTo-GatewayProcessRecord `
        -Process $ownerProcesses[0] `
        -Entrypoints $Entrypoints
    if ($null -eq $owner) {
        throw "The exact IPv4 loopback listener is not an exact installed gateway process."
    }

    $installed = @(Get-InstalledGatewayProcessRecords -Entrypoints $Entrypoints)
    if ($installed.Count -ne 1) {
        throw "Expected one exact installed gateway process, found $($installed.Count)."
    }
    if (-not (Test-GatewayProcessRecord -Expected $owner -Actual $installed[0])) {
        throw "The exact IPv4 loopback listener owner changed during process validation."
    }
    return $owner
}

function Test-GatewayProcessRecordPresent {
    param(
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][string[]]$Entrypoints
    )

    $processes = @(
        Get-CimInstance Win32_Process `
            -Filter "ProcessId = $([long]$Expected.ProcessId)" `
            -ErrorAction Stop
    )
    if ($processes.Count -eq 0) {
        return $false
    }
    if ($processes.Count -ne 1) {
        throw "The shutdown process ID did not resolve uniquely."
    }
    $actual = ConvertTo-GatewayProcessRecord `
        -Process $processes[0] `
        -Entrypoints $Entrypoints
    return (
        $null -ne $actual -and
        (Test-GatewayProcessRecord -Expected $Expected -Actual $actual)
    )
}

function ConvertTo-GatewayProofPayload {
    param([Parameter(Mandatory = $true)][string[]]$Components)

    $builder = [Text.StringBuilder]::new()
    foreach ($component in $Components) {
        if ($null -eq $component) {
            throw "Gateway shutdown proof components must not be null."
        }
        $byteLength = [Text.Encoding]::UTF8.GetByteCount($component)
        [void]$builder.Append(
            $byteLength.ToString([Globalization.CultureInfo]::InvariantCulture)
        )
        [void]$builder.Append(":")
        [void]$builder.Append($component)
    }
    return $builder.ToString()
}

function Get-HmacSha256Hex {
    param(
        [Parameter(Mandatory = $true)][string]$BearerToken,
        [Parameter(Mandatory = $true)][ValidateSet(
            "identity-request",
            "identity-response"
        )][string]$Purpose,
        [Parameter(Mandatory = $true)][string[]]$Values
    )

    $components = @(
        "copilot-im-gateway-shutdown",
        "1",
        $Purpose
    ) + @($Values)
    try {
        $payload = ConvertTo-GatewayProofPayload -Components $components
    }
    catch {
        throw "Gateway shutdown proof payload construction failed."
    }
    $hmac = [Security.Cryptography.HMACSHA256]::new(
        [Text.Encoding]::UTF8.GetBytes($BearerToken)
    )
    try {
        $payloadBytes = [Text.Encoding]::UTF8.GetBytes($payload)
        return (
            [BitConverter]::ToString($hmac.ComputeHash($payloadBytes))
        ).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $hmac.Dispose()
    }
}

function New-GatewayShutdownNonce {
    $nonceBytes = New-Object byte[] 32
    $random = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $random.GetBytes($nonceBytes)
    }
    finally {
        $random.Dispose()
    }
    return (
        [BitConverter]::ToString($nonceBytes)
    ).Replace("-", "").ToLowerInvariant()
}

function Request-AuthenticatedGatewayIdentity {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$BearerToken,
        [Parameter(Mandatory = $true)][object]$Owner
    )

    $clientNonce = New-GatewayShutdownNonce
    $requestProof = Get-HmacSha256Hex `
        -BearerToken $BearerToken `
        -Purpose "identity-request" `
        -Values @(
            [string]$Owner.ProcessId,
            [string]$Owner.CreationMarker,
            [string]$Port,
            $clientNonce,
            [string]$Owner.ExecutablePath,
            [string]$Owner.Entrypoint
        )
    $requestBody = @{
        protocolVersion = 1
        owner = @{
            pid = [long]$Owner.ProcessId
            creationMarker = [string]$Owner.CreationMarker
            executablePath = [string]$Owner.ExecutablePath
            entrypoint = [string]$Owner.Entrypoint
        }
        port = $Port
        clientNonce = $clientNonce
        requestProof = $requestProof
    } | ConvertTo-Json -Compress -Depth 3
    $requestBodyBytes = [Text.Encoding]::UTF8.GetBytes($requestBody)

    try {
        $response = Invoke-WebRequest `
            -Uri "http://127.0.0.1:$Port/v2/admin/identity" `
            -Method Post `
            -ContentType "application/json; charset=utf-8" `
            -Body $requestBodyBytes `
            -TimeoutSec 5 `
            -UseBasicParsing
        if ([int]$response.StatusCode -ne 200) {
            return $null
        }
        $identity = $response.Content | ConvertFrom-Json
        if ([int]$identity.protocolVersion -ne 1) {
            return $null
        }
        if (
            [int]$identity.apiVersion -ne 2 -or
            $null -eq $identity.capabilities -or
            -not (@($identity.capabilities) -contains "reservation-ownership") -or
            [string]$identity.instanceId -cnotmatch "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" -or
            [string]$identity.challengeId -cnotmatch "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" -or
            [long]$identity.owner.pid -ne [long]$Owner.ProcessId -or
            [string]$identity.owner.creationMarker -cne [string]$Owner.CreationMarker -or
            [string]$identity.owner.executablePath -cne [string]$Owner.ExecutablePath -or
            [string]$identity.owner.entrypoint -cne [string]$Owner.Entrypoint -or
            [int]$identity.port -ne $Port -or
            [string]$identity.clientNonce -cne $clientNonce -or
            [string]$identity.responseProof -cnotmatch "^[0-9a-f]{64}$"
        ) {
            return $null
        }
        $expiresAt = [long]$identity.expiresAt
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        if ($expiresAt -le $now -or $expiresAt -gt ($now + 15000)) {
            return $null
        }
        $expectedResponseProof = Get-HmacSha256Hex `
            -BearerToken $BearerToken `
            -Purpose "identity-response" `
            -Values @(
                "2",
                [string]$identity.instanceId,
                [string]$identity.challengeId,
                [string]$Owner.ProcessId,
                [string]$Owner.CreationMarker,
                [string]$Port,
                $clientNonce,
                [string]$expiresAt,
                [string]$Owner.ExecutablePath,
                [string]$Owner.Entrypoint
            )
        if ([string]$identity.responseProof -cne $expectedResponseProof) {
            return $null
        }
        return [pscustomobject]@{
            ProtocolVersion = 1
            InstanceId = [string]$identity.instanceId
            ChallengeId = [string]$identity.challengeId
            ClientNonce = $clientNonce
            ResponseProof = [string]$identity.responseProof
            ExpiresAt = $expiresAt
        }
    }
    catch {
        return $null
    }
}

function Read-GatewayShutdownHttpResponse {
    param(
        [Parameter(Mandatory = $true)]
        [Net.Sockets.NetworkStream]$Stream
    )

    $maximumHeaderBytes = 16 * 1024
    $maximumBodyBytes = 64 * 1024
    $responseTimeoutMilliseconds = 5000
    $responseTimer = [Diagnostics.Stopwatch]::StartNew()
    $headerBuilder = [Text.StringBuilder]::new()
    $previous3 = -1
    $previous2 = -1
    $previous1 = -1
    while ($true) {
        $remainingTimeout = (
            $responseTimeoutMilliseconds -
            [int]$responseTimer.ElapsedMilliseconds
        )
        if ($remainingTimeout -le 0) {
            throw "The gateway shutdown response timed out."
        }
        $Stream.ReadTimeout = $remainingTimeout
        $value = $Stream.ReadByte()
        if ($value -lt 0) {
            throw "The gateway shutdown response ended before its headers completed."
        }
        if ($value -gt 127) {
            throw "The gateway shutdown response headers were not ASCII."
        }
        [void]$headerBuilder.Append([char]$value)
        if ($headerBuilder.Length -gt $maximumHeaderBytes) {
            throw "The gateway shutdown response headers exceeded the size limit."
        }
        if (
            $previous3 -eq 13 -and
            $previous2 -eq 10 -and
            $previous1 -eq 13 -and
            $value -eq 10
        ) {
            break
        }
        $previous3 = $previous2
        $previous2 = $previous1
        $previous1 = $value
    }

    $headerText = $headerBuilder.ToString(
        0,
        $headerBuilder.Length - 4
    )
    $lines = @($headerText -split "`r`n")
    if (
        $lines.Count -lt 1 -or
        [string]$lines[0] -cnotmatch "^HTTP/1\.1 202(?: [\x20-\x7e]*)?$"
    ) {
        throw "The gateway shutdown response did not contain HTTP/1.1 status 202."
    }

    $headers = [Collections.Generic.Dictionary[string, string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    for ($index = 1; $index -lt $lines.Count; $index += 1) {
        $line = [string]$lines[$index]
        $separator = $line.IndexOf(":")
        if ($separator -le 0) {
            throw "The gateway shutdown response contained a malformed header."
        }
        $name = $line.Substring(0, $separator)
        $valueText = $line.Substring($separator + 1).Trim()
        if (
            $name -cnotmatch "^[A-Za-z0-9-]+$" -or
            $valueText -cnotmatch "^[\x09\x20-\x7e]*$" -or
            $headers.ContainsKey($name)
        ) {
            throw "The gateway shutdown response contained a malformed header."
        }
        $headers.Add($name, $valueText)
    }
    if ($headers.ContainsKey("Transfer-Encoding")) {
        throw "The gateway shutdown response used unsupported transfer encoding."
    }

    $buffer = New-Object byte[] 4096
    if ($headers.ContainsKey("Content-Length")) {
        $contentLengthText = $headers["Content-Length"]
        $contentLength = [long]0
        if (
            $contentLengthText -cnotmatch "^(?:0|[1-9][0-9]{0,5})$" -or
            -not [long]::TryParse(
                $contentLengthText,
                [Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,
                [ref]$contentLength
            ) -or
            $contentLength -gt $maximumBodyBytes
        ) {
            throw "The gateway shutdown response content length was invalid."
        }
        $remaining = $contentLength
        while ($remaining -gt 0) {
            $remainingTimeout = (
                $responseTimeoutMilliseconds -
                [int]$responseTimer.ElapsedMilliseconds
            )
            if ($remainingTimeout -le 0) {
                throw "The gateway shutdown response timed out."
            }
            $Stream.ReadTimeout = $remainingTimeout
            $requested = [Math]::Min([long]$buffer.Length, $remaining)
            $read = $Stream.Read($buffer, 0, [int]$requested)
            if ($read -le 0) {
                throw "The gateway shutdown response body ended early."
            }
            $remaining -= $read
        }
        return $true
    }

    $bodyBytes = 0
    while ($true) {
        $remainingTimeout = (
            $responseTimeoutMilliseconds -
            [int]$responseTimer.ElapsedMilliseconds
        )
        if ($remainingTimeout -le 0) {
            throw "The gateway shutdown response timed out."
        }
        $Stream.ReadTimeout = $remainingTimeout
        $read = $Stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) {
            break
        }
        $bodyBytes += $read
        if ($bodyBytes -gt $maximumBodyBytes) {
            throw "The gateway shutdown response body exceeded the size limit."
        }
    }
    return $true
}

function Invoke-AuthenticatedGatewayShutdown {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$BearerToken,
        [Parameter(Mandatory = $true)][object]$Challenge,
        [Parameter(Mandatory = $true)][object]$ExpectedOwner,
        [Parameter(Mandatory = $true)][string[]]$Entrypoints
    )

    if ($BearerToken -cnotmatch "^[A-Za-z0-9_-]{32,200}$") {
        throw "The gateway bearer token format is invalid."
    }
    $requestBody = @{
        protocolVersion = [int]$Challenge.ProtocolVersion
        instanceId = [string]$Challenge.InstanceId
        challengeId = [string]$Challenge.ChallengeId
        clientNonce = [string]$Challenge.ClientNonce
        responseProof = [string]$Challenge.ResponseProof
    } | ConvertTo-Json -Compress
    $requestBodyBytes = [Text.Encoding]::UTF8.GetBytes($requestBody)
    $client = $null
    $stream = $null
    try {
        $client = [Net.Sockets.TcpClient]::new()
        $client.SendTimeout = 5000
        $client.ReceiveTimeout = 5000
        $connectResult = $null
        $connectWaitHandle = $null
        try {
            $connectResult = $client.BeginConnect(
                [Net.IPAddress]::Loopback,
                $Port,
                $null,
                $null
            )
            $connectWaitHandle = $connectResult.AsyncWaitHandle
            if (-not $connectWaitHandle.WaitOne(5000)) {
                throw "The gateway shutdown TCP connection timed out."
            }
            $client.EndConnect($connectResult)
        }
        finally {
            if ($null -ne $connectWaitHandle) {
                $connectWaitHandle.Dispose()
            }
        }
        if (-not $client.Connected) {
            throw "The gateway shutdown TCP connection was not established."
        }
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $stream.WriteTimeout = 5000

        $actualOwner = Get-ValidatedGatewayListenerOwner `
            -Port $Port `
            -Entrypoints $Entrypoints
        if (-not (
            Test-GatewayProcessRecord `
                -Expected $ExpectedOwner `
                -Actual $actualOwner
        )) {
            throw "The listener owner changed after identity verification."
        }

        $contentLength = $requestBodyBytes.Length.ToString(
            [Globalization.CultureInfo]::InvariantCulture
        )
        $requestHeaders = @(
            "POST /v2/admin/shutdown HTTP/1.1",
            "Host: 127.0.0.1:$Port",
            "Authorization: Bearer $BearerToken",
            "Content-Type: application/json; charset=utf-8",
            "Content-Length: $contentLength",
            "Connection: close",
            "",
            ""
        ) -join "`r`n"
        $requestHeaderBytes = [Text.Encoding]::ASCII.GetBytes($requestHeaders)
        $stream.Write($requestHeaderBytes, 0, $requestHeaderBytes.Length)
        $stream.Write($requestBodyBytes, 0, $requestBodyBytes.Length)
        $stream.Flush()
        return Read-GatewayShutdownHttpResponse -Stream $stream
    }
    finally {
        try {
            if ($null -ne $stream) {
                $stream.Dispose()
            }
        }
        finally {
            if ($null -ne $client) {
                $client.Dispose()
            }
        }
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

    if ($Port -eq 0) {
        try {
            $installed = @(
                Get-InstalledGatewayProcessRecords -Entrypoints $entrypoints
            )
        }
        catch {
            throw (Get-ManualExitMessage `
                -Reason "The upgrade guard could not inspect running gateway processes.")
        }
        if ($installed.Count -ne 0) {
            throw (Get-ManualExitMessage `
                -Reason "A gateway process is running on an automatically assigned port.")
        }
        return
    }

    if (Test-LoopbackPortAvailable -Port $Port) {
        try {
            $installed = @(
                Get-InstalledGatewayProcessRecords -Entrypoints $entrypoints
            )
        }
        catch {
            throw (Get-ManualExitMessage `
                -Reason "The upgrade guard could not inspect running gateway processes.")
        }
        if ($installed.Count -ne 0) {
            throw (Get-ManualExitMessage `
                -Reason "A gateway process is running outside the configured loopback port.")
        }
        return
    }

    try {
        $owner = Get-ValidatedGatewayListenerOwner `
            -Port $Port `
            -Entrypoints $entrypoints
    }
    catch {
        throw (Get-ManualExitMessage `
            -Reason (
                "The upgrade guard could not resolve the exact owner of " +
                "127.0.0.1:$Port. $($_.Exception.Message)"
            ))
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
    if ($bearerToken -cnotmatch "^[A-Za-z0-9_-]{32,200}$") {
        throw (Get-ManualExitMessage `
            -Reason "The gateway token file is invalid, so authenticated v2 shutdown is unavailable.")
    }

    $challenge = Request-AuthenticatedGatewayIdentity `
        -Port $Port `
        -BearerToken $bearerToken `
        -Owner $owner
    if ($null -eq $challenge) {
        throw (Get-ManualExitMessage `
            -Reason (
                "The exact listener owner on 127.0.0.1:$Port did not prove " +
                "process-bound authenticated v2 gateway identity."
            ))
    }

    try {
        $shutdownAccepted = Invoke-AuthenticatedGatewayShutdown `
            -Port $Port `
            -BearerToken $bearerToken `
            -Challenge $challenge `
            -ExpectedOwner $owner `
            -Entrypoints $entrypoints
    }
    catch {
        throw (Get-ManualExitMessage `
            -Reason (
                "The upgrade guard could not send shutdown to the revalidated " +
                "listener owner. $($_.Exception.Message)"
            ))
    }
    if (-not $shutdownAccepted) {
        throw (Get-ManualExitMessage `
            -Reason "The listener on 127.0.0.1:$Port did not accept authenticated v2 shutdown.")
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ($true) {
        try {
            $ownerPresent = Test-GatewayProcessRecordPresent `
                -Expected $owner `
                -Entrypoints $entrypoints
        }
        catch {
            throw (Get-ManualExitMessage `
                -Reason "The upgrade guard could not confirm gateway process exit.")
        }
        if (
            (Test-LoopbackPortAvailable -Port $Port) -and
            -not $ownerPresent
        ) {
            try {
                $installed = @(
                    Get-InstalledGatewayProcessRecords -Entrypoints $entrypoints
                )
            }
            catch {
                throw (Get-ManualExitMessage `
                    -Reason "The upgrade guard could not confirm that installed gateway processes exited.")
            }
            if ($installed.Count -eq 0) {
                return
            }
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
