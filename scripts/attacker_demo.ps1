<#
.SYNOPSIS
    ZTA Gateway Attacker Demo - Run from ATTACKER machine (Windows PowerShell)
    Throttled to fit within one 30s scoring window without DoS-ing the gateway

.USAGE
    .\attacker_demo.ps1 -GatewayIP 192.168.50.1

.NOTES
    Triggers ALL 4 risk dimensions: Identity, Device, Network, Behavior
    Run from a DIFFERENT computer connected to the same network as the gateway
#>

param(
    [string]$GatewayIP = "192.168.50.1"
)

Write-Host "=== ZTA Gateway Attacker Demo ===" -ForegroundColor Cyan
Write-Host "Target: $GatewayIP" -ForegroundColor Yellow
Write-Host "This will trigger ALL 4 risk dimensions to demonstrate auto-ban" -ForegroundColor Gray
Write-Host ""

# Check tools
$missing = @()
Get-Command curl -ErrorAction SilentlyContinue -OutVariable _ | Out-Null; if (-not $_) { $missing += "curl" }
Get-Command dig -ErrorAction SilentlyContinue -OutVariable _ | Out-Null; if (-not $_) { $missing += "dig (bind-tools)" }
Get-Command ping -ErrorAction SilentlyContinue -OutVariable _ | Out-Null; if (-not $_) { $missing += "ping" }
if ($missing) { Write-Error "Missing tools: $($missing -join ', ')"; exit 1 }

function Run-Async { param([ScriptBlock]$sb) Start-Job -ScriptBlock $sb | Out-Null }

Write-Host "[1/4] IDENTITY RISK - 7 failed logins (20% weight)" -ForegroundColor Green
for ($i=1; $i -le 7; $i++) {
    curl -s -X POST "http://$GatewayIP/login" -d "username=admin&password=wrong$i" -H "Content-Type: application/x-www-form-urlencoded" > $null
    Start-Sleep -Milliseconds 200
}
Write-Host "    Done - Identity risk should be ~75-100" -ForegroundColor Gray

Write-Host ""
Write-Host "[2/4] NETWORK RISK - Blocklisted domains + suspicious ports (25% weight)" -ForegroundColor Green
# UNCACHED subdomains to force DNS queries through gateway
$jobs = @()
for ($i=1; $i -le 3; $i++) {
    $jobs += Start-Job { param($gw,$i) dig @$gw "demo-$($RANDOM)-$i.doubleclick.net" +short +time=1 } -ArgumentList $GatewayIP,$i
    $jobs += Start-Job { param($gw,$i) dig @$gw "demo-$($RANDOM)-$i.googlesyndication.com" +short +time=1 } -ArgumentList $GatewayIP,$i
}
# Suspicious ports: telnet(23), SMB(445), RDP(3389), IRC(6667)
23, 445, 3389, 6667 | ForEach-Object {
    $jobs += Start-Job { param($gw,$p)
        try { $tcp = New-Object Net.Sockets.TcpClient; $tcp.Connect($gw, $p); $tcp.Close() } catch {}
    } -ArgumentList $GatewayIP, $_
}
$jobs | Wait-Job | Out-Null
$jobs | Remove-Job
Write-Host "    Done - Network risk should be ~80-100" -ForegroundColor Gray

Write-Host ""
Write-Host "[3/4] BEHAVIOR RISK - Port sweep (35% weight, HIGHEST)" -ForegroundColor Green
$jobs = @()
for ($p=1; $p -le 300; $p++) {
    $jobs += Start-Job { param($gw,$p)
        try { $tcp = New-Object Net.Sockets.TcpClient; $tcp.Connect($gw, $p); $tcp.Close() } catch {}
    } -ArgumentList $GatewayIP, $p
    # Throttle: wait every 30 ports (~10 seconds total)
    if ($p % 30 -eq 0) { $jobs | Wait-Job | Out-Null; $jobs = @() }
}
$jobs | Wait-Job | Out-Null
Write-Host "    Done - Behavior risk should spike to 90-100" -ForegroundColor Gray

Write-Host ""
Write-Host "[4/4] BEHAVIOR RISK - DNS flood + large packets" -ForegroundColor Green
$jobs = @()
for ($i=1; $i -le 50; $i++) {
    $jobs += Start-Job { param($gw,$i) dig @$gw "flood-$($RANDOM)-$i.doubleclick.net" +short +time=1 } -ArgumentList $GatewayIP,$i
}
for ($i=1; $i -le 20; $i++) {
    $jobs += Start-Job { param($gw) ping -n 1 -l 1400 -w 1000 $gw } -ArgumentList $GatewayIP
}
$jobs | Wait-Job | Out-Null
Write-Host "    Done - Additional behavior + network spikes" -ForegroundColor Gray

Write-Host ""
Write-Host "=== ATTACK COMPLETE ===" -ForegroundColor Cyan
Write-Host "Check the admin dashboard at http://$GatewayIP/admin within 30 seconds" -ForegroundColor Yellow
Write-Host "Expected: Device status -> BANNED (composite risk >= 70)" -ForegroundColor Green
Write-Host ""
Write-Host "If not banned yet:" -ForegroundColor Gray
Write-Host "  - Wait for scoring window (runs every 30s)"
Write-Host "  - Check baseline learning: first 10 min = learning mode (behavior capped at 5)"
Write-Host "  - Run integration test for guaranteed demo: python tests/test_integration.py"