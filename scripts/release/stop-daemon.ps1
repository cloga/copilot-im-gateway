param(
    [Parameter(Mandatory = $true)][string]$InstallDirectory,
    [string]$DataDirectory,
    [string]$TokenFile,
    [int]$Port = -1,
    [ValidateRange(1, 300)][int]$TimeoutSeconds = 30,
    [ValidateRange(16, 300)][int]$FallbackLeaseWaitSeconds = 16
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

function Get-ProcessById {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    return Get-CimInstance Win32_Process `
        -Filter "ProcessId = $ProcessId" `
        -ErrorAction SilentlyContinue
}

function Get-RevalidatedGatewayProcess {
    param(
        [Parameter(Mandatory = $true)][object]$Candidate,
        [Parameter(Mandatory = $true)][string[]]$Entrypoints
    )

    $processId = [int]$Candidate.ProcessId
    $current = Get-ProcessById -ProcessId $processId
    if ($null -eq $current) {
        return $null
    }
    if (
        [string]$current.CreationDate -ne [string]$Candidate.CreationDate -or
        -not (Test-GatewayProcess -Process $current -Entrypoints $Entrypoints)
    ) {
        throw "Process $processId changed identity before shutdown; refusing to stop it."
    }
    return $current
}

function Get-LoopbackListeningPorts {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    return @(
        Get-NetTCPConnection `
            -OwningProcess $ProcessId `
            -State Listen `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalAddress -eq "127.0.0.1" } |
            ForEach-Object { [int]$_.LocalPort }
    )
}

function Invoke-AuthenticatedGatewayShutdown {
    param(
        [Parameter(Mandatory = $true)][int[]]$Ports,
        [Parameter(Mandatory = $true)][string]$BearerToken
    )

    $unsupportedResponses = 0
    $failures = [Collections.Generic.List[string]]::new()
    foreach ($candidatePort in $Ports) {
        try {
            $response = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$candidatePort/v2/admin/shutdown" `
                -Method Post `
                -Headers @{ Authorization = "Bearer $BearerToken" } `
                -TimeoutSec 5 `
                -UseBasicParsing
            if ([int]$response.StatusCode -eq 202) {
                return "Accepted"
            }
            [void]$failures.Add("port $candidatePort returned HTTP $([int]$response.StatusCode)")
        }
        catch {
            $statusCode = $null
            if (
                $_.Exception.PSObject.Properties.Name -contains "Response" -and
                $null -ne $_.Exception.Response
            ) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            if ($statusCode -in @(404, 405, 501)) {
                $unsupportedResponses += 1
            }
            elseif ($null -eq $statusCode) {
                [void]$failures.Add("port $candidatePort did not return an HTTP response")
            }
            else {
                [void]$failures.Add("port $candidatePort returned HTTP $statusCode")
            }
        }
    }

    if ($unsupportedResponses -eq $Ports.Count) {
        return "Unsupported"
    }
    throw "Authenticated gateway shutdown was not accepted: $($failures -join '; ')."
}

function Wait-ForExactProcessExit {
    param(
        [Parameter(Mandatory = $true)][object]$Candidate,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $processId = [int]$Candidate.ProcessId
    try {
        Wait-Process -Id $processId -Timeout $TimeoutSeconds -ErrorAction Stop
    }
    catch {
        $current = Get-ProcessById -ProcessId $processId
        if (
            $null -ne $current -and
            [string]$current.CreationDate -eq [string]$Candidate.CreationDate
        ) {
            throw "Gateway daemon process $processId did not terminate."
        }
    }

    $remaining = Get-ProcessById -ProcessId $processId
    if (
        $null -ne $remaining -and
        [string]$remaining.CreationDate -eq [string]$Candidate.CreationDate
    ) {
        throw "Gateway daemon process $processId is still running."
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

function Invoke-StopGatewayDaemon {
    param(
        [Parameter(Mandatory = $true)][string]$InstallDirectory,
        [string]$DataDirectory,
        [string]$TokenFile,
        [int]$Port = -1,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 30,
        [ValidateRange(16, 300)][int]$FallbackLeaseWaitSeconds = 16
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

    $gatewayProcesses = @(
        Get-CimInstance Win32_Process |
            Where-Object {
                Test-GatewayProcess -Process $_ -Entrypoints $entrypoints
            }
    )
    if ($gatewayProcesses.Count -eq 0) {
        return
    }

    if (-not (Test-Path -LiteralPath $resolvedTokenFile -PathType Leaf)) {
        throw "Gateway token file was not found; refusing unauthenticated process termination."
    }
    $bearerToken = (Get-Content -LiteralPath $resolvedTokenFile -Raw).Trim()
    if ($bearerToken.Length -lt 32) {
        throw "Gateway token file is invalid; refusing unauthenticated process termination."
    }

    $portsToRelease = [Collections.Generic.HashSet[int]]::new()
    foreach ($gatewayProcess in $gatewayProcesses) {
        $processId = [int]$gatewayProcess.ProcessId
        $listeningPorts = @(Get-LoopbackListeningPorts -ProcessId $processId)
        if ($listeningPorts.Count -eq 0) {
            throw "Gateway daemon process $processId has no loopback listener; refusing to terminate it."
        }
        foreach ($listeningPort in $listeningPorts) {
            [void]$portsToRelease.Add($listeningPort)
        }
        $orderedPorts = @(
            if ($Port -ne 0 -and $listeningPorts -contains $Port) {
                $Port
            }
            $listeningPorts |
                Where-Object { $_ -ne $Port } |
                Sort-Object -Unique
        )

        $current = Get-RevalidatedGatewayProcess `
            -Candidate $gatewayProcess `
            -Entrypoints $entrypoints
        if ($null -eq $current) {
            continue
        }
        $shutdownResult = Invoke-AuthenticatedGatewayShutdown `
            -Ports $orderedPorts `
            -BearerToken $bearerToken
        if ($shutdownResult -eq "Accepted") {
            Wait-ForExactProcessExit `
                -Candidate $gatewayProcess `
                -TimeoutSeconds $TimeoutSeconds
            continue
        }
        if ($shutdownResult -ne "Unsupported") {
            throw "Unexpected gateway shutdown result '$shutdownResult'."
        }

        $current = Get-RevalidatedGatewayProcess `
            -Candidate $gatewayProcess `
            -Entrypoints $entrypoints
        if ($null -eq $current) {
            continue
        }
        Stop-Process -Id $processId -Force -ErrorAction Stop
        Wait-ForExactProcessExit `
            -Candidate $gatewayProcess `
            -TimeoutSeconds $TimeoutSeconds
        Start-Sleep -Seconds $FallbackLeaseWaitSeconds
    }

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    foreach ($releasedPort in $portsToRelease) {
        while (-not (Test-LoopbackPortAvailable -Port $releasedPort)) {
            if ([DateTime]::UtcNow -ge $deadline) {
                throw "Gateway loopback port 127.0.0.1:$releasedPort was not released."
            }
            Start-Sleep -Milliseconds 100
        }
    }
}

if ($MyInvocation.InvocationName -ne ".") {
    Invoke-StopGatewayDaemon @PSBoundParameters
}
