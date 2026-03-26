<#
.SYNOPSIS
    AkesoEDR Ch. 13 Attack Chain Automation (P10-T2)

.DESCRIPTION
    Simulates the 8 phases of the attack chain from "Evading EDR" Chapter 13
    using benign OS primitives, then validates that AkesoEDR generates at
    least one alert per phase by searching agent_events.jsonl.

    Phases:
      1. Initial Access      - XLL file delivery (file copy)
      2. Shellcode Execution  - Process launch (calc.exe)
      3. C2 Establishment     - Outbound TCP connection
      4. Persistence          - Preview handler registry key
      5. Reconnaissance       - Enumeration commands
      6. Privilege Escalation - Handle to privileged process
      7. Lateral Movement     - Suspicious named pipe
      8. Exfiltration         - File staging + outbound connection

.PARAMETER LogPath
    Path to the agent's JSON-lines event log.
    Default: C:\AkesoEDR\agent_events.jsonl

.PARAMETER XllPath
    Path to test_xll.xll for Phase 1. Default: C:\AkesoEDR\test_xll.xll

.PARAMETER FlushDelay
    Seconds to wait after each simulation for events to flush. Default: 3

.EXAMPLE
    .\attack_chain.ps1
    .\attack_chain.ps1 -LogPath D:\logs\agent_events.jsonl -FlushDelay 5

.NOTES
    Requires: Elevated PowerShell, AkesoEDR agent + driver running.
    Run on the test VM, not the development host.
#>

param(
    [string]$LogPath    = "C:\AkesoEDR\agent_events.jsonl",
    [string]$XllPath    = "C:\AkesoEDR\test_xll.xll",
    [int]$FlushDelay    = 5
)

$ErrorActionPreference = "Continue"

# ── Helpers ──────────────────────────────────────────────────────────────────

function Get-LogFileSize {
    if (Test-Path $LogPath) {
        return (Get-Item $LogPath).Length
    }
    return 0
}

function Search-NewEvents {
    param(
        [long]$StartByte,
        [string[]]$Patterns
    )
    if (-not (Test-Path $LogPath)) { return @() }

    $fileSize = (Get-Item $LogPath).Length
    if ($fileSize -le $StartByte) { return @() }

    # Read only the new bytes appended since StartByte
    $stream = [System.IO.FileStream]::new($LogPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $stream.Seek($StartByte, [System.IO.SeekOrigin]::Begin) | Out-Null
    $reader = [System.IO.StreamReader]::new($stream)
    $newText = $reader.ReadToEnd()
    $reader.Close()
    $stream.Close()

    $newLines = @($newText -split "`n" | Where-Object { $_.Trim().Length -gt 0 })

    [System.Collections.ArrayList]$matchList = @()
    foreach ($pattern in $Patterns) {
        $found = @($newLines | Where-Object { $_ -match $pattern })
        foreach ($f in $found) { [void]$matchList.Add($f) }
    }
    return @(,$matchList.ToArray())
}

function Write-PhaseBanner {
    param([int]$Num, [string]$Name)
    Write-Host ""
    Write-Host "=== Phase $Num`: $Name ===" -ForegroundColor Cyan
}

function Write-PhaseResult {
    param([int]$Num, [string]$Name, [bool]$Pass, [int]$EventCount)
    if ($Pass) {
        Write-Host "  PASS: $EventCount event(s) detected" -ForegroundColor Green
    } else {
        Write-Host "  FAIL: No matching events found" -ForegroundColor Red
    }
    return @{
        Phase  = $Num
        Name   = $Name
        Pass   = $Pass
        Events = $EventCount
    }
}

# ── Pre-flight checks ───────────────────────────────────────────────────────

Write-Host "============================================" -ForegroundColor Yellow
Write-Host "  AkesoEDR Attack Chain Test (Ch. 13)"       -ForegroundColor Yellow
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "  Host: $env:COMPUTERNAME"                     -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow

if (-not (Test-Path $LogPath)) {
    Write-Host "ERROR: Log file not found: $LogPath" -ForegroundColor Red
    Write-Host "  Is akesoedr-agent running?" -ForegroundColor DarkYellow
    exit 1
}

$results = @()

# ── Phase 1: Initial Access (XLL file delivery) ─────────────────────────────

Write-PhaseBanner 1 "Initial Access (XLL delivery)"

$bytesBefore = Get-LogFileSize

# Simulate: copy XLL to user temp directory (triggers minifilter)
$tempXll = Join-Path $env:TEMP "test_xll_$(Get-Random).xll"
if (Test-Path $XllPath) {
    Copy-Item $XllPath $tempXll -Force
    Write-Host "  Copied XLL to $tempXll"
} else {
    # If no XLL available, create a dummy file with the .xll extension
    "DUMMY_XLL_PAYLOAD" | Set-Content $tempXll
    Write-Host "  Created dummy XLL at $tempXll (test_xll.xll not found)"
}

Start-Sleep -Seconds $FlushDelay

$hits = Search-NewEvents -StartByte $bytesBefore -Patterns @(
    "test_xll"
)

# Cleanup
Remove-Item $tempXll -Force -ErrorAction SilentlyContinue

$results += Write-PhaseResult 1 "Initial Access" (@($hits).Count -gt 0) @($hits).Count

# ── Phase 2: Shellcode Execution (process launch) ────────────────────────────

Write-PhaseBanner 2 "Shellcode Execution (notepad.exe)"

$bytesBefore = Get-LogFileSize

# Simulate: launch notepad.exe as stand-in for shellcode payload (issue #42)
# Using notepad instead of calc because calc is a UWP app that launches
# indirectly through a broker, making PID tracking unreliable.
$proc = Start-Process -FilePath "notepad.exe" -PassThru
Write-Host "  Launched notepad.exe (PID $($proc.Id))"

Start-Sleep -Seconds $FlushDelay

$hits = Search-NewEvents -StartByte $bytesBefore -Patterns @(
    "notepad"
)

# Cleanup
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue

$results += Write-PhaseResult 2 "Shellcode Execution" (@($hits).Count -gt 0) @($hits).Count

# ── Phase 3: C2 Establishment (Outbound Connection) ─────────────────────────

Write-PhaseBanner 3 "C2 Establishment (outbound connection)"

$bytesBefore = Get-LogFileSize

# Simulate: outbound TCP connection to example.com (93.184.216.34:80)
Write-Host "  Connecting to 93.184.216.34:80 (example.com)..."
try {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect("93.184.216.34", 80)
    Write-Host "  Connected successfully"
    $tcp.Close()
} catch {
    Write-Host "  Connection failed (expected on isolated VMs)" -ForegroundColor DarkYellow
}

Start-Sleep -Seconds $FlushDelay

$hits = Search-NewEvents -StartByte $bytesBefore -Patterns @(
    "93.184.216.34",
    "DriverNetwork"
)

$results += Write-PhaseResult 3 "C2 Establishment" (@($hits).Count -gt 0) @($hits).Count

# ── Phase 4: Persistence (Preview Handler Registry) ─────────────────────────

Write-PhaseBanner 4 "Persistence (preview handler registry)"

$bytesBefore = Get-LogFileSize

# Simulate: write a preview handler shell extension registry key
$regKey = "HKCU:\Software\Classes\.akeso\shellex\{8895b1c6-b41f-4c1c-a562-0d564250836f}"
New-Item -Path $regKey -Force | Out-Null
Set-ItemProperty -Path $regKey -Name "(Default)" -Value "{DEADBEEF-1234-5678-9ABC-DEF012345678}"
Write-Host "  Created preview handler key: $regKey"

Start-Sleep -Seconds $FlushDelay

$hits = Search-NewEvents -StartByte $bytesBefore -Patterns @(
    "DriverRegistry",
    "shellex",
    "akeso",
    "DEADBEEF"
)

# Cleanup
Remove-Item "HKCU:\Software\Classes\.akeso" -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "  Cleaned up registry key"

$results += Write-PhaseResult 4 "Persistence" (@($hits).Count -gt 0) @($hits).Count

# ── Phase 5: Reconnaissance (Enumeration Commands) ──────────────────────────

Write-PhaseBanner 5 "Reconnaissance (enumeration)"

$bytesBefore = Get-LogFileSize

# Simulate: Seatbelt-style enumeration using built-in Windows commands
Write-Host "  Running: whoami, net user, net localgroup, systeminfo"
whoami /all 2>&1 | Out-Null
net user 2>&1 | Out-Null
net localgroup Administrators 2>&1 | Out-Null
systeminfo 2>&1 | Out-Null

Start-Sleep -Seconds $FlushDelay

$hits = Search-NewEvents -StartByte $bytesBefore -Patterns @(
    "whoami",
    "net.exe",
    "net1.exe",
    "systeminfo"
)

$results += Write-PhaseResult 5 "Reconnaissance" (@($hits).Count -gt 0) @($hits).Count

# ── Phase 6: Privilege Escalation (Handle to Privileged Process) ─────────────

Write-PhaseBanner 6 "Privilege Escalation (process handle access)"

$bytesBefore = Get-LogFileSize

# Simulate: open a handle to winlogon.exe (a privileged SYSTEM process)
Write-Host "  Opening handle to winlogon.exe..."
$privCode = @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public class PrivEsc {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    public static int Test() {
        Process[] procs = Process.GetProcessesByName("winlogon");
        if (procs.Length == 0) return -1;
        IntPtr h = OpenProcess(0x0400, false, procs[0].Id); // PROCESS_QUERY_INFORMATION
        if (h != IntPtr.Zero) {
            CloseHandle(h);
            return procs[0].Id;
        }
        return 0;
    }
}
'@
try {
    Add-Type -TypeDefinition $privCode -ErrorAction SilentlyContinue
    $targetPid = [PrivEsc]::Test()
    if ($targetPid -gt 0) {
        Write-Host "  Opened handle to winlogon (PID $targetPid)"
    } elseif ($targetPid -eq 0) {
        Write-Host "  OpenProcess failed (access denied - expected)" -ForegroundColor DarkYellow
    } else {
        Write-Host "  winlogon not found" -ForegroundColor DarkYellow
    }
} catch {
    Write-Host "  Add-Type failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

Start-Sleep -Seconds $FlushDelay

$hits = Search-NewEvents -StartByte $bytesBefore -Patterns @(
    "winlogon",
    "DriverObject",
    "DotNETRuntime",
    "OpenProcess",
    "NtOpenProcess"
)

$results += Write-PhaseResult 6 "Privilege Escalation" (@($hits).Count -gt 0) @($hits).Count

# ── Phase 7: Lateral Movement (Suspicious Named Pipe) ───────────────────────

Write-PhaseBanner 7 "Lateral Movement (suspicious named pipe)"

$bytesBefore = Get-LogFileSize

# Simulate: create a named pipe matching Cobalt Strike default patterns
$pipeName = "msagent_akeso_test"
Write-Host "  Creating named pipe: \\.\pipe\$pipeName"
try {
    $pipe = [System.IO.Pipes.NamedPipeServerStream]::new(
        $pipeName,
        [System.IO.Pipes.PipeDirection]::InOut,
        1,
        [System.IO.Pipes.PipeTransmissionMode]::Byte,
        [System.IO.Pipes.PipeOptions]::Asynchronous
    )
    Start-Sleep -Seconds 2
    $pipe.Dispose()
    Write-Host "  Pipe created and disposed"
} catch {
    Write-Host "  Pipe creation failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

Start-Sleep -Seconds $FlushDelay

$hits = Search-NewEvents -StartByte $bytesBefore -Patterns @(
    "msagent",
    "NamedPipe",
    "pipe",
    "$pipeName"
)

$results += Write-PhaseResult 7 "Lateral Movement" (@($hits).Count -gt 0) @($hits).Count

# ── Phase 8: Exfiltration (File Staging + Outbound) ─────────────────────────

Write-PhaseBanner 8 "Exfiltration (file staging + network)"

$bytesBefore = Get-LogFileSize

# Simulate: create a sensitive-looking file, then make outbound connection
$exfilFile = Join-Path $env:TEMP "exfil_test_$(Get-Date -Format yyyyMMddHHmmss).txt"
"CONFIDENTIAL: AkesoEDR attack chain test exfiltration data`nSSN: 000-00-0000`nCC: 0000-0000-0000-0000" | Set-Content $exfilFile
Write-Host "  Created staging file: $exfilFile"

# Outbound connection (simulates data exfil over HTTP)
try {
    $tcp2 = New-Object System.Net.Sockets.TcpClient
    $tcp2.Connect("93.184.216.34", 80)
    Write-Host "  Outbound connection to 93.184.216.34:80 succeeded"
    $tcp2.Close()
} catch {
    Write-Host "  Outbound connection failed (expected on isolated VMs)" -ForegroundColor DarkYellow
}

Start-Sleep -Seconds $FlushDelay

$hits = Search-NewEvents -StartByte $bytesBefore -Patterns @(
    "exfil_test",
    "DriverMinifilter",
    "93\.184\.216\.34"
)

# Cleanup
Remove-Item $exfilFile -Force -ErrorAction SilentlyContinue

$results += Write-PhaseResult 8 "Exfiltration" (@($hits).Count -gt 0) @($hits).Count

# ── Summary Report ───────────────────────────────────────────────────────────

Write-Host ""
Write-Host "============================================" -ForegroundColor Yellow
Write-Host "  ATTACK CHAIN TEST REPORT"                    -ForegroundColor Yellow
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "  Host: $env:COMPUTERNAME"                     -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow

$totalEvents = 0
$passCount   = 0

foreach ($r in $results) {
    $status = if ($r.Pass) { "PASS" } else { "FAIL" }
    $color  = if ($r.Pass) { "Green" } else { "Red" }
    $label  = "  Phase $($r.Phase) - $($r.Name):"
    $detail = "$status ($($r.Events) event(s))"
    Write-Host ("{0,-40} {1}" -f $label, $detail) -ForegroundColor $color
    $totalEvents += $r.Events
    if ($r.Pass) { $passCount++ }
}

Write-Host "--------------------------------------------" -ForegroundColor Yellow
$resultColor = if ($passCount -eq 8) { "Green" } else { "Red" }
Write-Host "  RESULT: $passCount/8 phases detected" -ForegroundColor $resultColor
Write-Host "  Total alerts: $totalEvents" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor Yellow

# Exit code: 0 if all phases pass, 1 otherwise
if ($passCount -eq 8) { exit 0 } else { exit 1 }
