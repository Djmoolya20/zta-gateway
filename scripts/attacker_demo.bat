@echo off
REM Attacker Demo Script - Run from ATTACKER machine (Windows)
REM Throttled to fit within one 30s scoring window without DoS-ing the gateway
REM Usage: attacker_demo.bat <GATEWAY_IP>
REM Example: attacker_demo.bat 192.168.50.1

set GATEWAY=%~1
if "%GATEWAY%"=="" set GATEWAY=192.168.50.1

echo === ZTA Gateway Attacker Demo ===
echo Target: %GATEWAY%
echo This will trigger ALL 4 risk dimensions to demonstrate auto-ban
echo.

REM Check for required tools
where curl >nul 2>&1 || (echo Missing: curl & exit /b 1)
where dig >nul 2>&1 || (echo Missing: dig (bind-tools) & exit /b 1)
where ping >nul 2>&1 || (echo Missing: ping & exit /b 1)

echo [1/4] IDENTITY RISK - 7 failed logins (20%% weight)
for /L %%i in (1,1,7) do (
    curl -s -X POST "http://%GATEWAY%/login" -d "username=admin&password=wrong%%i" -H "Content-Type: application/x-www-form-urlencoded" >nul
    timeout /t 1 >nul
)
echo     Done - Identity risk should be ~75-100
echo.

echo [2/4] NETWORK RISK - Blocklisted domains + suspicious ports (25%% weight)
REM Use UNCACHED subdomains to force DNS queries through gateway
for /L %%i in (1,1,3) do (
    start /b dig @"%GATEWAY%" "demo-%%random%%-%%i.doubleclick.net" +short +time=1 >nul
    start /b dig @"%GATEWAY%" "demo-%%random%%-%%i.googlesyndication.com" +short +time=1 >nul
)
REM Suspicious ports: telnet(23), SMB(445), RDP(3389), IRC(6667)
for %%p in (23 445 3389 6667) do (
    start /b powershell -Command "try { $tcp = New-Object Net.Sockets.TcpClient; $tcp.Connect('%GATEWAY%', %%p); $tcp.Close() } catch {}" >nul
)
timeout /t 3 >nul
echo     Done - Network risk should be ~80-100
echo.

echo [3/4] BEHAVIOR RISK - Port sweep (35%% weight, HIGHEST)
REM 300 ports throttled over ~10 seconds
for /L %%p in (1,1,300) do (
    start /b powershell -Command "try { $tcp = New-Object Net.Sockets.TcpClient; $tcp.Connect('%GATEWAY%', %%p); $tcp.Close() } catch {}" >nul
    REM Throttle: wait every 30 ports
    set /a "mod=%%p %% 30"
    if !mod! equ 0 timeout /t 1 >nul
)
timeout /t 5 >nul
echo     Done - Behavior risk should spike to 90-100
echo.

echo [4/4] BEHAVIOR RISK - DNS flood + large packets
for /L %%i in (1,1,50) do (
    start /b dig @"%GATEWAY%" "flood-%%random%%-%%i.doubleclick.net" +short +time=1 >nul
)
for /L %%i in (1,1,20) do (
    start /b ping -n 1 -l 1400 -w 1000 %GATEWAY% >nul
)
timeout /t 3 >nul
echo     Done - Additional behavior + network spikes
echo.

echo === ATTACK COMPLETE ===
echo Check the admin dashboard at http://%GATEWAY%/admin within 30 seconds
echo Expected: Device status -^> BANNED (composite risk ^>= 70)
echo.
echo If not banned yet:
echo   - Wait for scoring window (runs every 30s)
echo   - Check baseline learning: first 10 min = learning mode (behavior capped at 5)
echo   - Run integration test for guaranteed demo: python tests/test_integration.py

pause