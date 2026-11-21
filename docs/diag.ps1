<#
  Rescue Support - read-only diagnostics for a misbehaving Windows 10 PC.

  Default run changes NOTHING: it only reads system state and writes a text report to
  C:\ProgramData\RescueSupport\diag-<timestamp>.txt. Nothing is uploaded anywhere.

  Optional, administrator-initiated actions (each one is explicit):
    -SfcVerify     sfc /verifyonly          (read-only integrity scan, slow)
    -SfcRepair     sfc /scannow             (REPAIRS protected system files)
    -DismScan      DISM /Online /Cleanup-Image /ScanHealth     (read-only, slow)
    -DismRepair    DISM /Online /Cleanup-Image /RestoreHealth  (REPAIRS the component store, needs Windows Update)

  Examples (over SSH, from an elevated session):
    powershell -NoProfile -ExecutionPolicy Bypass -File diag.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File diag.ps1 -Hours 72 -SfcVerify

  Windows PowerShell 5.1 compatible, ASCII only.
#>
[CmdletBinding()]
param(
    [int]$Hours = 48,
    [switch]$SfcVerify,
    [switch]$SfcRepair,
    [switch]$DismScan,
    [switch]$DismRepair,
    [string]$OutFile = ''
)
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$dir = Join-Path $env:ProgramData 'RescueSupport'
if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
if (-not $OutFile) { $OutFile = Join-Path $dir ("diag-{0}.txt" -f (Get-Date).ToString('yyyyMMdd-HHmmss')) }
Set-Content -LiteralPath $OutFile -Value ("Rescue Support diagnostics {0} on {1}" -f (Get-Date).ToString('s'), $env:COMPUTERNAME) -Encoding ASCII

function Out-Both([string]$Text) {
    Write-Host $Text
    Add-Content -LiteralPath $OutFile -Value $Text -Encoding ASCII
}
function Section([string]$Title) { Out-Both ''; Out-Both ('=== ' + $Title + ' ' + ('=' * [Math]::Max(3, 70 - $Title.Length))) }
function Show($Obj) {
    $t = ($Obj | Out-String -Width 220).TrimEnd()
    if ($t) { Out-Both $t } else { Out-Both '(nothing)' }
}
function Try-Do([string]$Name, [scriptblock]$Block) {
    try { & $Block } catch { Out-Both ("[{0}] could not be read: {1}" -f $Name, $_.Exception.Message) }
}
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Run-Native([string]$Exe, [string[]]$ArgList) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $o = & $Exe @ArgList 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $old }
    return @{ ExitCode = $LASTEXITCODE; Output = @($o) }
}

$isAdmin = Test-IsAdmin
$since = (Get-Date).AddHours(-1 * [Math]::Abs($Hours))

# ---------------------------------------------------------------------------------------------
Section 'System'
Try-Do 'os' {
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $ubr = $cv.UBR
    Out-Both ("Windows     : {0}" -f $os.Caption)
    Out-Both ("Version      : {0}  build {1}.{2}  ({3})" -f $cv.DisplayVersion, $os.BuildNumber, $ubr, $os.OSArchitecture)
    Out-Both ("Install date : {0}" -f $os.InstallDate)
    Out-Both ("Last boot    : {0}" -f $os.LastBootUpTime)
    $up = (Get-Date) - $os.LastBootUpTime
    Out-Both ("Uptime       : {0}d {1}h {2}m   (Fast Startup can hide a long uptime; a real restart is different from shutdown)" -f $up.Days, $up.Hours, $up.Minutes)
    Out-Both ("Admin shell  : {0}" -f $isAdmin)
    $cs = Get-CimInstance Win32_ComputerSystem
    Out-Both ("Machine      : {0} {1}, domain/workgroup {2}" -f $cs.Manufacturer, $cs.Model, $cs.Domain)
    $bios = Get-CimInstance Win32_BIOS
    Out-Both ("BIOS         : {0} {1}" -f $bios.SMBIOSBIOSVersion, $bios.ReleaseDate)
}
Try-Do 'pending' {
    $r = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $r += 'Component Based Servicing' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $r += 'Windows Update' }
    $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($v -and $v.PendingFileRenameOperations) { $r += 'PendingFileRenameOperations' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending') { $r += 'PackagesPending' }
    Out-Both ("Pending restart: {0}" -f $(if ($r.Count) { 'YES - ' + ($r -join ', ') } else { 'no' }))
}

# ---------------------------------------------------------------------------------------------
Section 'CPU and memory'
Try-Do 'cpu' {
    $cpu = Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, LoadPercentage, MaxClockSpeed
    Show $cpu
    $s = (Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 5 -ErrorAction Stop).CounterSamples | ForEach-Object { [Math]::Round($_.CookedValue, 1) }
    Out-Both ("CPU % over 5s : {0}" -f ($s -join ', '))
}
Try-Do 'mem' {
    $os = Get-CimInstance Win32_OperatingSystem
    $tot = [Math]::Round($os.TotalVisibleMemorySize / 1MB, 2); $free = [Math]::Round($os.FreePhysicalMemory / 1MB, 2)
    Out-Both ("RAM          : {0} GB total, {1} GB free ({2}% used)" -f $tot, $free, [Math]::Round(100 * (1 - $free / $tot), 0))
    $pf = Get-CimInstance Win32_PageFileUsage | Select-Object Name, AllocatedBaseSize, CurrentUsage, PeakUsage
    Show $pf
    Out-Both ("Physical memory modules:")
    Show (Get-CimInstance Win32_PhysicalMemory | Select-Object BankLabel, @{n='GB';e={[Math]::Round($_.Capacity/1GB,1)}}, Speed, Manufacturer)
}
Try-Do 'top' {
    Out-Both 'Top processes by CPU time:'
    Show (Get-Process | Sort-Object CPU -Descending | Select-Object -First 8 Name, Id, @{n='CPU_s';e={[Math]::Round($_.CPU,0)}}, @{n='WS_MB';e={[Math]::Round($_.WorkingSet64/1MB,0)}}, Handles)
    Out-Both 'Top processes by memory:'
    Show (Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 8 Name, Id, @{n='WS_MB';e={[Math]::Round($_.WorkingSet64/1MB,0)}}, @{n='PagedPool_KB';e={[Math]::Round($_.PagedMemorySize64/1KB,0)}}, Handles)
}

# ---------------------------------------------------------------------------------------------
Section 'Disks'
Try-Do 'physdisk' { Show (Get-PhysicalDisk | Select-Object FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus, @{n='GB';e={[Math]::Round($_.Size/1GB,0)}}) }
Try-Do 'reliability' { Show (Get-PhysicalDisk | Get-StorageReliabilityCounter | Select-Object DeviceId, Temperature, Wear, ReadErrorsTotal, WriteErrorsTotal, PowerOnHours) }
Try-Do 'smart' {
    $fp = Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop
    foreach ($d in $fp) { Out-Both ("SMART predicts failure: {0}  ({1})" -f $d.PredictFailure, $d.InstanceName) }
}
Try-Do 'volumes' { Show (Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter, FileSystemLabel, FileSystem, HealthStatus, @{n='SizeGB';e={[Math]::Round($_.Size/1GB,1)}}, @{n='FreeGB';e={[Math]::Round($_.SizeRemaining/1GB,1)}}, @{n='Free%';e={if ($_.Size) {[Math]::Round(100*$_.SizeRemaining/$_.Size,0)}}}) }
Try-Do 'dirty' { foreach ($l in (Get-Volume | Where-Object DriveLetter).DriveLetter) { $r = Run-Native 'fsutil.exe' @('dirty', 'query', ($l + ':')); Out-Both (($r.Output -join ' ').Trim()) } }

# ---------------------------------------------------------------------------------------------
Section ("Event log errors, last {0} hours" -f $Hours)
Try-Do 'events' {
    foreach ($log in @('System', 'Application')) {
        Out-Both ''
        Out-Both ("-- {0}: Critical/Error grouped by source and ID (top 15)" -f $log)
        $ev = Get-WinEvent -FilterHashtable @{ LogName = $log; Level = 1, 2; StartTime = $since } -ErrorAction SilentlyContinue
        if (-not $ev) { Out-Both '(none)'; continue }
        Show ($ev | Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 15 Count, Name)
    }
}
Try-Do 'key-events' {
    Out-Both ''
    Out-Both '-- Known problem signatures'
    $sigs = @(
        @{ L = 'System';      Id = 41;   P = 'Microsoft-Windows-Kernel-Power'; T = 'Unexpected shutdown / power loss (Kernel-Power 41)' },
        @{ L = 'System';      Id = 1001; P = 'Microsoft-Windows-WER-SystemErrorReporting'; T = 'Blue screen (BugCheck)' },
        @{ L = 'System';      Id = 6008; P = 'EventLog'; T = 'Previous shutdown was unexpected' },
        @{ L = 'System';      Id = 7, 11, 15, 51, 55, 98, 129, 153; P = $null; T = 'Disk / NTFS / storage errors (IDs 7,11,15,51,55,98,129,153)' },
        @{ L = 'System';      Id = 17, 18, 19, 20; P = 'Microsoft-Windows-WHEA-Logger'; T = 'Hardware errors (WHEA)' },
        @{ L = 'System';      Id = 4101; P = 'Display'; T = 'Display driver stopped responding and recovered' },
        @{ L = 'System';      Id = 7000, 7001, 7009, 7011, 7022, 7023, 7024, 7031, 7034; P = 'Service Control Manager'; T = 'Service failures / timeouts' },
        @{ L = 'Application'; Id = 1000; P = 'Application Error'; T = 'Application crashes' },
        @{ L = 'Application'; Id = 1002; P = 'Application Hang'; T = 'Application hangs' }
    )
    foreach ($s in $sigs) {
        $f = @{ LogName = $s.L; Id = $s.Id; StartTime = $since }
        if ($s.P) { $f['ProviderName'] = $s.P }
        $e = @(Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue)
        Out-Both ("{0,4} x  {1}" -f $e.Count, $s.T)
        foreach ($x in ($e | Select-Object -First 2)) {
            $m = ($x.Message -replace '\s+', ' '); if ($m.Length -gt 200) { $m = $m.Substring(0, 200) + '...' }
            Out-Both ("        {0}  id {1}: {2}" -f $x.TimeCreated.ToString('MM-dd HH:mm'), $x.Id, $m)
        }
    }
}

# ---------------------------------------------------------------------------------------------
Section 'Explorer and desktop shell'
Try-Do 'explorer' {
    $ex = @(Get-Process explorer -ErrorAction SilentlyContinue)
    Out-Both ("explorer.exe processes: {0}" -f $ex.Count)
    if ($ex.Count) { Show ($ex | Select-Object Id, SessionId, @{n='Started';e={$_.StartTime}}, @{n='WS_MB';e={[Math]::Round($_.WorkingSet64/1MB,0)}}, Responding, Handles) }
    foreach ($n in 'dwm', 'sihost', 'ShellExperienceHost', 'StartMenuExperienceHost', 'SearchHost', 'SearchUI', 'RuntimeBroker', 'ctfmon') {
        $p = @(Get-Process $n -ErrorAction SilentlyContinue)
        if ($p.Count) { Out-Both ("{0,-24}: {1} running, {2} MB" -f $n, $p.Count, [Math]::Round(($p | Measure-Object WorkingSet64 -Sum).Sum / 1MB, 0)) }
        else { Out-Both ("{0,-24}: not running" -f $n) }
    }
}
Try-Do 'winlogon' {
    $w = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Out-Both ("Winlogon Shell    : {0}   (expected: explorer.exe)" -f $w.Shell)
    Out-Both ("Winlogon Userinit : {0}   (expected: C:\Windows\system32\userinit.exe,)" -f $w.Userinit)
}
Try-Do 'shellsvc' {
    Show (Get-Service ShellHWDetection, Themes, UxSms, ProfSvc, Audiosrv, 'CDPUserSvc*', 'StateRepository', 'TabletInputService', 'WSearch', 'SysMain' -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType)
}
Try-Do 'shellcrash' {
    Out-Both 'Recent crashes/hangs of shell components:'
    $e = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000, 1002; StartTime = $since } -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'explorer\.exe|ShellExperienceHost|StartMenuExperienceHost|SearchHost|SearchUI|sihost|dwm\.exe|ctfmon|TextInputHost' })
    Out-Both ("{0} event(s)" -f $e.Count)
    foreach ($x in ($e | Select-Object -First 6)) {
        $m = ($x.Message -replace '\s+', ' '); if ($m.Length -gt 330) { $m = $m.Substring(0, 330) + '...' }
        Out-Both ("  {0} {1}" -f $x.TimeCreated.ToString('MM-dd HH:mm'), $m)
    }
}
Try-Do 'dumps' {
    $d = @(Get-ChildItem 'C:\Windows\Minidump', 'C:\Windows\MEMORY.DMP', "$env:LOCALAPPDATA\CrashDumps" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 8)
    Out-Both ("Crash dump files found: {0}" -f $d.Count)
    if ($d.Count) { Show ($d | Select-Object FullName, LastWriteTime, @{n='MB';e={[Math]::Round($_.Length/1MB,1)}}) }
}
Try-Do 'profiles' {
    Show (Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special } | Select-Object LocalPath, Loaded, LastUseTime, Status)
    $users = @(Get-CimInstance Win32_ComputerSystem).UserName
    Out-Both ("Interactive user: {0}" -f $users)
}
Try-Do 'startup' { Out-Both 'Startup commands (Run keys, Startup folders):'; Show (Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User) }

# ---------------------------------------------------------------------------------------------
Section 'Devices with problems (Device Manager)'
Try-Do 'pnp' {
    $bad = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 })
    Out-Both ("{0} device(s) report an error" -f $bad.Count)
    if ($bad.Count) { Show ($bad | Select-Object Name, PNPClass, ConfigManagerErrorCode, Status, DeviceID) }
}

# ---------------------------------------------------------------------------------------------
Section 'Windows Update and servicing'
Try-Do 'wusvc' { Show (Get-Service wuauserv, bits, cryptsvc, TrustedInstaller, UsoSvc, msiserver -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType) }
Try-Do 'hotfix' { Out-Both 'Most recent updates installed:'; Show (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID, Description, InstalledOn) }
Try-Do 'wuevents' {
    Out-Both ''
    Out-Both 'Windows Update client problems (WindowsUpdateClient/Operational, Level 2 = error):'
    $e = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'; Level = 2; StartTime = (Get-Date).AddDays(-30) } -ErrorAction SilentlyContinue | Select-Object -First 6)
    Out-Both ("{0} error event(s) in the last 30 days" -f $e.Count)
    foreach ($x in $e) { $m = ($x.Message -replace '\s+', ' '); if ($m.Length -gt 220) { $m = $m.Substring(0, 220) + '...' }; Out-Both ("  {0} id {1}: {2}" -f $x.TimeCreated.ToString('MM-dd HH:mm'), $x.Id, $m) }
}
Try-Do 'sd' {
    $p = 'C:\Windows\SoftwareDistribution'
    if (Test-Path $p) { $sz = (Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum; Out-Both ("SoftwareDistribution size: {0} MB" -f [Math]::Round($sz / 1MB, 0)) }
}

# ---------------------------------------------------------------------------------------------
Section 'System file integrity'
Try-Do 'dism-check' {
    if (-not $isAdmin) { Out-Both 'Skipped: needs an elevated session.'; return }
    Out-Both 'DISM /CheckHealth (fast, read-only):'
    $r = Run-Native 'dism.exe' @('/Online', '/Cleanup-Image', '/CheckHealth')
    Show ($r.Output | Where-Object { $_ -and $_.Trim() })
}
Try-Do 'cbs' {
    $cbs = 'C:\Windows\Logs\CBS\CBS.log'
    if (Test-Path $cbs) {
        $t = Get-Content $cbs -Tail 4000 -ErrorAction SilentlyContinue
        $bad = @($t | Where-Object { $_ -match 'Cannot repair|corrupt|Hashes for file member .* do not match' } | Select-Object -Last 8)
        Out-Both ("CBS.log (last 4000 lines): {0} corruption-related line(s)" -f $bad.Count)
        foreach ($l in $bad) { Out-Both ("  " + ($l -replace '\s+', ' ')) }
    }
}
if ($SfcVerify) {
    Out-Both ''; Out-Both 'sfc /verifyonly (read-only, this takes a while)...'
    $r = Run-Native 'sfc.exe' @('/verifyonly'); Show (($r.Output -join "`n") -replace "`0", '')
}
if ($DismScan) {
    Out-Both ''; Out-Both 'DISM /ScanHealth (read-only, this takes a while)...'
    $r = Run-Native 'dism.exe' @('/Online', '/Cleanup-Image', '/ScanHealth'); Show ($r.Output | Where-Object { $_ -and $_.Trim() })
}
if ($SfcRepair) {
    if (-not $isAdmin) { Out-Both 'sfc /scannow needs an elevated session.' } else {
        Out-Both ''; Out-Both 'ADMIN-INITIATED: sfc /scannow (repairs protected system files; details in CBS.log)...'
        $r = Run-Native 'sfc.exe' @('/scannow'); Show (($r.Output -join "`n") -replace "`0", '')
    }
}
if ($DismRepair) {
    if (-not $isAdmin) { Out-Both 'DISM /RestoreHealth needs an elevated session.' } else {
        Out-Both ''; Out-Both 'ADMIN-INITIATED: DISM /RestoreHealth (repairs the component store using Windows Update)...'
        $r = Run-Native 'dism.exe' @('/Online', '/Cleanup-Image', '/RestoreHealth'); Show ($r.Output | Where-Object { $_ -and $_.Trim() })
    }
}

# ---------------------------------------------------------------------------------------------
Section 'Security and network (summary)'
Try-Do 'defender' {
    $m = Get-MpComputerStatus -ErrorAction Stop
    Out-Both ("Defender: realtime={0} antivirus={1} signatures={2} (age {3} days) last quick scan={4}" -f $m.RealTimeProtectionEnabled, $m.AntivirusEnabled, $m.AntivirusSignatureVersion, $m.AntivirusSignatureAge, $m.QuickScanEndTime)
    $t = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -First 5)
    Out-Both ("Recent Defender detections: {0}" -f $t.Count)
    foreach ($x in $t) { Out-Both ("  {0} threat id {1} {2}" -f $x.InitialDetectionTime, $x.ThreatID, ($x.Resources -join ', ')) }
}
Try-Do 'net' {
    Show (Get-NetIPConfiguration | Select-Object InterfaceAlias, @{n='IPv4';e={$_.IPv4Address.IPAddress}}, @{n='Gateway';e={$_.IPv4DefaultGateway.NextHop}}, @{n='DNS';e={$_.DNSServer.ServerAddresses -join ','}})
    Out-Both ("Internet (TCP 443 to 1.1.1.1): {0}" -f (Test-NetConnection 1.1.1.1 -Port 443 -WarningAction SilentlyContinue).TcpTestSucceeded)
}
Try-Do 'rescue' {
    Show (Get-Service sshd, Tailscale -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType)
}

Section 'Done'
Out-Both ("Report saved locally (not uploaded): {0}" -f $OutFile)
