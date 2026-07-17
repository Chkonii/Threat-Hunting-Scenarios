param(
    [string]$Subnet = "10.2.0",
    [int]$StartHost = 1,
    [int]$EndHost = 254,
    [int[]]$Ports = @(22, 80, 443, 135, 445, 139, 3389),
    [int]$TimeoutMs = 200   
)

$log = "C:\ProgramData\portscan.log"
"[{0}] Scan Started {1}.{2}-{3} ports {4}" -f `
    [Datetime]::UtcNow.ToString("o"), $Subnet, $StartHost, $EndHost, ($Ports -join ",") |
    Add-Content $log


foreach ($h in $StartHost..$EndHost) {
    $ip = "$Subnet.$h"
    foreach ($p in $Ports) {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $iar = $client.BeginConnect($ip, $p, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs) -and $client.Connected) {
                $msg = "OPEN $ip`:$p"
                Write-Host $msg -ForegroundColor Green
                Add-Content $log ("[{0}] {1}" -f [DateTime]::UtcNow.ToString("o"), $msg)

            }
        } catch {} finally { $client.Close() }
    }
}
"[{0}] Scan complete." -f [DateTime]::UtcNow.ToString("o") | Add-Content $log
