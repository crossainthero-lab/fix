<#
  Rescue Support installer  -  authorised remote-support helper for Windows 10 (x64).

  What it does (and nothing else):
    1. Installs the Windows "OpenSSH Server" optional feature (if missing) and starts the sshd service.
    2. Adds ONE firewall rule that lets TCP/22 in ONLY from Tailscale addresses (100.64.0.0/10).
    3. Installs Tailscale from pkgs.tailscale.com (SHA-256 + Authenticode checked) and joins it to the
       helper's tailnet using a one-time key you type at a hidden prompt (or a login link).
    4. Adds the helper's SSH PUBLIC key (marked "rescue-support") to the authorised keys.
    5. Prints a summary. Everything is recorded in C:\ProgramData\RescueSupport and fully reversible:
         C:\ProgramData\RescueSupport\uninstall.cmd

  It does not disable Defender/UAC, open router ports, create accounts or set passwords.
  Source: https://github.com/crossainthero-lab/fix

  Usage (from Administrator CMD, via the r.cmd launcher):
    r.cmd              install / re-run safely
    r.cmd status       show what is installed, change nothing
    r.cmd check        pre-flight checks only, change nothing
    r.cmd uninstall    remove everything this tool added

  Must stay Windows PowerShell 5.1 compatible and pure ASCII.
#>
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Status,
    [switch]$CheckOnly,
    [switch]$Yes,                 # skip the confirmation question
    [string]$PublicKey = '',      # override the built-in helper public key (one line)
    [string]$AuthKeyFile = ''     # read the Tailscale key from this file instead of prompting
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# ----------------------------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------------------------
$script:Version      = '1.0.0'
$script:HelperKey    = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILPnXnGuT+Wuk5tsi15Vix8r6+3NNlAtSRVkF5ir1H94 rescue-support'
$script:KeyMarker    = 'rescue-support'
$script:Dir          = Join-Path $env:ProgramData 'RescueSupport'
$script:StateFile    = Join-Path $script:Dir 'state.json'
$script:LogFile      = $null
$script:FwRuleName   = 'RescueSupport-SSH-Tailscale'
$script:FwRuleLabel  = 'Rescue Support - SSH from Tailscale only'
$script:TsRanges     = @('100.64.0.0/10', 'fd7a:115c:a1e0::/48')
$script:MsiBase      = 'https://pkgs.tailscale.com/stable'
$script:State        = [ordered]@{}
$script:RebootNeeded = $false
$script:Warnings     = New-Object System.Collections.ArrayList
$script:Secrets      = New-Object System.Collections.ArrayList
$script:CapName      = 'OpenSSH.Server~~~~0.0.1.0'

# ----------------------------------------------------------------------------------------------
# Logging (redacts Tailscale keys everywhere)
# ----------------------------------------------------------------------------------------------
function Hide-Secrets([string]$Text) {
    if ($null -eq $Text) { return '' }
    $t = [regex]::Replace($Text, 'tskey-[A-Za-z0-9_-]+', 'tskey-[REDACTED]')
    foreach ($s in $script:Secrets) { if ($s -and $s.Length -ge 8) { $t = $t.Replace($s, '[REDACTED]') } }
    return $t
}

function Write-RLog([string]$Level, [string]$Message) {
    $clean = Hide-Secrets $Message
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value ("{0} [{1}] {2}" -f $stamp, $Level, $clean) -Encoding ASCII } catch { }
    }
    switch ($Level) {
        'STEP' { Write-Host ''; Write-Host ("== {0}" -f $clean) -ForegroundColor Cyan }
        'OK'   { Write-Host ("   [ OK ] {0}" -f $clean) -ForegroundColor Green }
        'WARN' { Write-Host ("   [WARN] {0}" -f $clean) -ForegroundColor Yellow; [void]$script:Warnings.Add($clean) }
        'ERR'  { Write-Host ("   [FAIL] {0}" -f $clean) -ForegroundColor Red }
        'LOG'  { }
        default { Write-Host ("   {0}" -f $clean) }
    }
}

function Stop-Rescue([string]$Message, [int]$Code = 1) {
    $ex = New-Object System.Exception $Message
    $ex.Data['RescueCode'] = $Code
    throw $ex
}

# ----------------------------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Native([string]$Exe, [string[]]$ArgList, [switch]$Quiet) {
    # Runs a native command, logs its (redacted) output, returns @{ExitCode; Output}. Never throws on stderr text.
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        $out = & $Exe @ArgList 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $old }
    if (-not $Quiet) { foreach ($l in @($out)) { if ($l -and $l.Trim()) { Write-RLog 'LOG' ("  > " + $l) } } }
    return @{ ExitCode = $code; Output = @($out) }
}

function Get-CurrentSid { return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }

function Get-Prop($Obj, [string]$Name, $Default = $null) {
    if ($null -eq $Obj) { return $Default }
    $p = $Obj.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return $Default }
    return $p.Value
}

function Save-State {
    try {
        $script:State['updated'] = (Get-Date).ToString('o')
        ($script:State | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $script:StateFile -Encoding ASCII
    } catch { Write-RLog 'WARN' ("Could not save state file: " + $_.Exception.Message) }
}

function Load-State {
    $script:State = [ordered]@{}
    if (Test-Path -LiteralPath $script:StateFile) {
        try {
            $o = Get-Content -LiteralPath $script:StateFile -Raw | ConvertFrom-Json
            foreach ($p in $o.PSObject.Properties) { $script:State[$p.Name] = $p.Value }
        } catch { Write-RLog 'WARN' ("State file unreadable, ignoring: " + $_.Exception.Message) }
    }
}

function Get-StateBool([string]$Name) {
    if ($script:State.Contains($Name)) { return ($script:State[$Name] -eq $true) }
    return $false
}

function Initialize-WorkDir {
    if (-not (Test-Path -LiteralPath $script:Dir)) { New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null }
    # Admin/SYSTEM only (SIDs, so this works in any Windows language).
    [void](Invoke-Native 'icacls.exe' @($script:Dir, '/inheritance:r', '/grant:r', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F') -Quiet)
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $script:LogFile = Join-Path $script:Dir ("rescue-{0}.log" -f $stamp)
    Write-RLog 'LOG' ("Rescue Support {0} started by {1}\{2}" -f $script:Version, $env:USERDOMAIN, $env:USERNAME)
}

function Test-TcpPort([string]$HostName, [int]$Port, [int]$TimeoutMs = 6000) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $c.BeginConnect($HostName, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $c.EndConnect($iar); return $true
    } catch { return $false } finally { $c.Close() }
}

function Get-PendingReboot {
    $r = New-Object System.Collections.ArrayList
    $keys = @{
        'Component Servicing' = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        'Windows Update'      = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    }
    foreach ($k in $keys.Keys) { if (Test-Path $keys[$k]) { [void]$r.Add($k) } }
    try {
        $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($v -and $v.PendingFileRenameOperations) { [void]$r.Add('Pending file renames') }
    } catch { }
    return @($r)
}

function Get-TailscaleExe {
    foreach ($p in @("$env:ProgramFiles\Tailscale\tailscale.exe", "${env:ProgramFiles(x86)}\Tailscale\tailscale.exe")) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    $c = Get-Command tailscale.exe -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    return $null
}

function Find-TailscaleProductCode {
    $code = $null
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
            if ($p -and (Get-Prop $p 'DisplayName') -eq 'Tailscale' -and $_.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') { $code = $_.PSChildName }
        }
    }
    return $code
}

function Get-TailscaleStatus([string]$Exe) {
    # Returns the parsed `tailscale status --json`, or $null when the daemon is not answering.
    if (-not $Exe) { return $null }
    $r = Invoke-Native $Exe @('status', '--json') -Quiet
    if ($r.ExitCode -ne 0) { return $null }
    try { return (($r.Output -join "`n") | ConvertFrom-Json) } catch { return $null }
}

function Get-TailscaleIPv4([string]$Exe) {
    $r = Invoke-Native $Exe @('ip', '-4') -Quiet
    if ($r.ExitCode -ne 0) { return $null }
    foreach ($l in $r.Output) { if ($l -match '^\s*(100\.\d+\.\d+\.\d+)\s*$') { return $Matches[1] } }
    return $null
}

# ----------------------------------------------------------------------------------------------
# Pre-flight
# ----------------------------------------------------------------------------------------------
function Test-Preflight {
    Write-RLog 'STEP' 'Checking this computer'
    if (-not (Test-IsAdmin)) {
        Stop-Rescue 'This window is not elevated. Close it, then open "Command Prompt" with Run as administrator (Ctrl+Shift+Enter from the Start search).' 10
    }
    Write-RLog 'OK' 'Running as Administrator'

    $os = Get-CimInstance Win32_OperatingSystem
    $build = [int]$os.BuildNumber
    Write-RLog 'OK' ("{0} (build {1}, {2})" -f $os.Caption, $build, $os.OSArchitecture)
    if ($build -lt 17763) {
        Stop-Rescue ("Windows build {0} is too old: the OpenSSH Server optional feature needs Windows 10 version 1809 (build 17763) or newer." -f $build) 11
    }
    if ($build -ge 22000) { Write-RLog 'WARN' 'This is Windows 11 or newer, not Windows 10. Continuing - the same steps apply.' }
    if ($os.ProductType -ne 1) { Write-RLog 'WARN' 'This is a Windows Server edition, not a desktop edition. Continuing.' }
    $arch = $env:PROCESSOR_ARCHITEW6432; if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    switch -Regex ($arch) {
        'AMD64' { $script:Arch = 'amd64' }
        'ARM64' { $script:Arch = 'arm64'; Write-RLog 'WARN' 'ARM64 PC: only x64 is the tested target.' }
        default { $script:Arch = 'x86';   Write-RLog 'WARN' 'Not a 64-bit PC: only x64 is the tested target.' }
    }
    if ($arch -ne 'AMD64' -and [Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        Write-RLog 'WARN' '32-bit PowerShell on a 64-bit system; the launcher should have used 64-bit.'
    }

    Write-RLog 'STEP' 'Checking internet access'
    $bad = @()
    foreach ($h in @('pkgs.tailscale.com', 'controlplane.tailscale.com', 'login.tailscale.com')) {
        if (Test-TcpPort $h 443) { Write-RLog 'OK' ("Reached {0}:443" -f $h) } else { $bad += $h; Write-RLog 'ERR' ("Cannot reach {0}:443" -f $h) }
    }
    if ($bad.Count -gt 0) {
        $hint = 'Check the network cable / Wi-Fi, a proxy or VPN, and that the Windows date and time are correct (a wrong clock breaks HTTPS).'
        Stop-Rescue ("No usable internet connection to Tailscale ({0}). {1}" -f ($bad -join ', '), $hint) 12
    }

    $pend = Get-PendingReboot
    if ($pend.Count -gt 0) {
        Write-RLog 'WARN' ("Windows already has a restart pending ({0}). Feature installs may fail or only finish after a restart." -f ($pend -join ', '))
    }
}

# ----------------------------------------------------------------------------------------------
# OpenSSH Server
# ----------------------------------------------------------------------------------------------
function Install-OpenSshServer {
    Write-RLog 'STEP' 'OpenSSH Server'
    $cap = $null
    try { $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction Stop | Select-Object -First 1 }
    catch {
        Stop-Rescue ("Windows could not list optional features ({0}). The Windows servicing stack or Windows Update may be damaged - this is a real problem on this PC, not something the script can fix." -f $_.Exception.Message) 20
    }
    if (-not $cap) { Stop-Rescue 'This Windows has no "OpenSSH.Server" optional feature available.' 20 }
    $script:CapName = $cap.Name

    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($cap.State -eq 'Installed' -or $svc) {
        Write-RLog 'OK' 'OpenSSH Server is already installed - leaving the installation as it is'
        if (-not $script:State.Contains('sshdInstalledByUs')) { $script:State['sshdInstalledByUs'] = $false }
    } else {
        Write-RLog 'INFO' 'Installing the OpenSSH Server optional feature (needs Windows Update / feature-on-demand; can take a few minutes)...'
        try {
            $res = Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop
        } catch {
            $m = $_.Exception.Message
            $hint = ''
            if ($m -match '0x800f0954|0x800f0950|0x800f081f|0x8024402c|0x80240438|0x80072ee7') {
                $hint = ' Typical causes: Windows Update/WSUS policy blocks optional features, no route to Windows Update, or damaged component store.'
            }
            Stop-Rescue ("Windows refused to install OpenSSH Server: {0}.{1} Nothing else was changed. Manual alternative: https://github.com/PowerShell/Win32-OpenSSH/releases" -f $m, $hint) 21
        }
        if ($res -and (Get-Prop $res 'RestartNeeded' $false)) { $script:RebootNeeded = $true }
        $script:State['sshdInstalledByUs'] = $true
        Save-State
        Write-RLog 'OK' 'OpenSSH Server installed'
    }

    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $svc) {
        if ($script:RebootNeeded) { Stop-Rescue 'OpenSSH Server was installed but Windows needs a restart before the sshd service exists. Restart the PC, then run the same command again.' 22 }
        Stop-Rescue 'The sshd service is missing even though the feature reports as installed.' 22
    }

    if (-not $script:State.Contains('sshdPrevStartMode')) {
        $cim = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue
        $script:State['sshdPrevStartMode'] = $(if ($cim) { $cim.StartMode } else { 'Manual' })
        $script:State['sshdPrevRunning']   = ($svc.Status -eq 'Running')
        Save-State
    }
    try {
        Set-Service -Name sshd -StartupType Automatic -ErrorAction Stop
        if ((Get-Service sshd).Status -ne 'Running') { Start-Service -Name sshd -ErrorAction Stop }
    } catch {
        Stop-Rescue ("Could not start the sshd service: {0}. Look in Event Viewer > Applications and Services Logs > OpenSSH > Operational." -f $_.Exception.Message) 23
    }
    Write-RLog 'OK' 'sshd service is running and set to start automatically'

    # First start generates host keys and %ProgramData%\ssh\sshd_config.
    $cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
    for ($i = 0; $i -lt 15 -and -not (Test-Path -LiteralPath $cfg); $i++) { Start-Sleep -Seconds 1 }
    if (-not (Test-Path -LiteralPath $cfg)) { Write-RLog 'WARN' 'sshd_config was not created yet; key setup will use the default layout.' }
}

function Get-SshdConfigText {
    $cfg = Join-Path $env:ProgramData 'ssh\sshd_config'
    if (Test-Path -LiteralPath $cfg) { return (Get-Content -LiteralPath $cfg -Raw) }
    return ''
}

function Add-HelperKey {
    Write-RLog 'STEP' 'SSH public key for the helper'
    $key = $PublicKey; if (-not $key) { $key = $script:HelperKey }
    $key = $key.Trim()
    if ($key -notmatch '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com)\s+[A-Za-z0-9+/=]+(\s.*)?$') {
        Write-RLog 'WARN' 'No valid helper public key is configured; skipping key setup (password login still works).'
        return
    }
    $parts = $key -split '\s+'
    $blob  = $parts[1]
    $line  = "{0} {1} {2}" -f $parts[0], $parts[1], $script:KeyMarker

    $isAdmin = Test-IsAdmin
    $cfgText = Get-SshdConfigText
    $useShared = $isAdmin -and ($cfgText -match '(?im)^\s*Match\s+Group\s+administrators') -and ($cfgText -match 'administrators_authorized_keys')
    $sid = Get-CurrentSid
    if ($useShared) {
        $target = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    } else {
        $sshDir = Join-Path $env:USERPROFILE '.ssh'
        if (-not (Test-Path -LiteralPath $sshDir)) { New-Item -ItemType Directory -Path $sshDir -Force | Out-Null }
        $target = Join-Path $sshDir 'authorized_keys'
    }

    $existed = Test-Path -LiteralPath $target
    $text = ''
    if ($existed) { $text = [IO.File]::ReadAllText($target) }
    if ($text -match [regex]::Escape($blob)) {
        Write-RLog 'OK' ("Helper key is already present in {0}" -f $target)
    } else {
        if ($text.Length -gt 0 -and -not $text.EndsWith("`n")) { $text += "`r`n" }
        $text += $line + "`r`n"
        [IO.File]::WriteAllText($target, $text, (New-Object System.Text.UTF8Encoding($false)))
        if (-not $existed) {
            # Only set permissions on a file we created ourselves; Microsoft documents this ACL for the shared file.
            if ($useShared) { [void](Invoke-Native 'icacls.exe' @($target, '/inheritance:r', '/grant', '*S-1-5-32-544:F', '/grant', '*S-1-5-18:F') -Quiet) }
            else            { [void](Invoke-Native 'icacls.exe' @($target, '/inheritance:r', '/grant', ('*' + $sid + ':F'), '/grant', '*S-1-5-18:F', '/grant', '*S-1-5-32-544:F') -Quiet) }
            $script:State['keyFileCreated'] = $true
        }
        Write-RLog 'OK' ("Helper public key added to {0}" -f $target)
    }
    $script:State['keyFile'] = $target
    if (-not $script:State.Contains('keyFileCreated')) { $script:State['keyFileCreated'] = $false }
    Save-State
}

# ----------------------------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------------------------
function Set-SshFirewall {
    Write-RLog 'STEP' 'Windows Firewall'
    $rule = Get-NetFirewallRule -Name $script:FwRuleName -ErrorAction SilentlyContinue
    if ($rule) {
        if ($rule.Enabled -ne 'True') { Enable-NetFirewallRule -Name $script:FwRuleName }
        Write-RLog 'OK' ("Rule '{0}' already exists" -f $script:FwRuleLabel)
    } else {
        New-NetFirewallRule -Name $script:FwRuleName -DisplayName $script:FwRuleLabel `
            -Description 'Created by Rescue Support. Allows SSH only from Tailscale addresses. Remove with uninstall.cmd.' `
            -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress $script:TsRanges -Profile Any -Enabled True | Out-Null
        $script:State['firewallRuleCreated'] = $true
        Write-RLog 'OK' ("Created rule '{0}' (TCP 22 from {1} only)" -f $script:FwRuleLabel, ($script:TsRanges -join ', '))
    }

    # The built-in rule that Windows adds with OpenSSH allows SSH from ANY address. If we installed OpenSSH
    # ourselves, turn that one off (re-enabled on uninstall). A pre-existing rule is the owner's choice: warn only.
    $builtin = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
    if ($builtin -and $builtin.Enabled -eq 'True') {
        if (Get-StateBool 'sshdInstalledByUs') {
            Disable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP'
            $script:State['builtinRuleDisabledByUs'] = $true
            Write-RLog 'OK' 'Disabled the built-in "OpenSSH-Server-In-TCP" rule (it allowed SSH from any network); it is restored on uninstall'
        } else {
            Write-RLog 'WARN' 'An existing firewall rule "OpenSSH-Server-In-TCP" allows SSH from any network. It was there before, so it was NOT changed.'
        }
    }
    Save-State
}

# ----------------------------------------------------------------------------------------------
# Tailscale
# ----------------------------------------------------------------------------------------------
function Install-Tailscale {
    Write-RLog 'STEP' 'Tailscale'
    $exe = Get-TailscaleExe
    if ($exe) {
        Write-RLog 'OK' ("Tailscale is already installed ({0})" -f $exe)
        if (-not $script:State.Contains('tailscaleInstalledByUs')) { $script:State['tailscaleInstalledByUs'] = $false }
        return $exe
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $dl = Join-Path $script:Dir 'download'
    if (-not (Test-Path -LiteralPath $dl)) { New-Item -ItemType Directory -Path $dl -Force | Out-Null }
    $tmp = Join-Path $dl 'tailscale-latest.msi'
    # Ask Tailscale which file is the current stable MSI for this CPU, then download exactly that file.
    $file = $null
    try { $meta = Invoke-RestMethod -Uri ($script:MsiBase + '/?mode=json') -TimeoutSec 60; $file = [string]$meta.MSIs.($script:Arch) }
    catch { Stop-Rescue ("Could not read the Tailscale package list from pkgs.tailscale.com: " + $_.Exception.Message) 30 }
    if ($file -notmatch '^tailscale-setup-[\d.]+-(amd64|arm64|x86)\.msi$') { Stop-Rescue ("Unexpected Tailscale package name: {0}" -f $file) 31 }
    $finalUrl = "{0}/{1}" -f $script:MsiBase, $file
    Write-RLog 'INFO' ("Downloading Tailscale (official package) from {0}" -f $finalUrl)

    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (Test-Path -LiteralPath $curl) {
        $r = Invoke-Native $curl @('-fL', '--proto', '=https', '--retry', '3', '--connect-timeout', '20', '-sS', '-o', $tmp, $finalUrl) -Quiet
        if ($r.ExitCode -ne 0) { Stop-Rescue ("Download failed (curl exit {0}): {1}" -f $r.ExitCode, ($r.Output -join ' ')) 30 }
    } else {
        try { Invoke-WebRequest -UseBasicParsing -Uri $finalUrl -OutFile $tmp -TimeoutSec 900 } catch { Stop-Rescue ("Download failed: " + $_.Exception.Message) 30 }
    }
    $size = (Get-Item -LiteralPath $tmp).Length
    if ($size -lt 5MB) { Stop-Rescue ("Downloaded file is only {0} bytes - not a valid installer." -f $size) 31 }

    # 1) SHA-256 against Tailscale's published checksum
    $want = $null
    try {
        $c = (Invoke-WebRequest -UseBasicParsing -Uri ($finalUrl + '.sha256') -TimeoutSec 60).Content
        if ($c -is [byte[]]) { $c = [Text.Encoding]::ASCII.GetString($c) }
        $want = ([string]$c).Trim().ToLower()
    } catch { }
    $got = (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash.ToLower()
    if ($want -and $want -match '^[0-9a-f]{64}') {
        if ($got -ne $want.Substring(0, 64)) { Remove-Item -LiteralPath $tmp -Force; Stop-Rescue ("Checksum mismatch for Tailscale installer (got {0}). Deleted." -f $got) 32 }
        Write-RLog 'OK' ("SHA-256 matches Tailscale's published checksum ({0}...)" -f $got.Substring(0, 16))
    } else {
        Write-RLog 'WARN' 'Could not fetch the published checksum; relying on the digital signature only.'
    }
    # 2) Authenticode signature
    $sig = Get-AuthenticodeSignature -LiteralPath $tmp
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Tailscale Inc\.') {
        $subj = $(if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { 'none' })
        Remove-Item -LiteralPath $tmp -Force
        Stop-Rescue ("Digital signature check failed (status {0}, signer {1}). Deleted." -f $sig.Status, $subj) 33
    }
    Write-RLog 'OK' 'Digital signature is valid: Tailscale Inc.'

    $msiLog = Join-Path $script:Dir 'tailscale-msi.log'
    Write-RLog 'INFO' 'Installing Tailscale silently...'
    $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', ('"{0}"' -f $tmp), '/qn', '/norestart', 'TS_NOLAUNCH=1', '/L*v', ('"{0}"' -f $msiLog)) -Wait -PassThru
    if ($p.ExitCode -eq 3010) { $script:RebootNeeded = $true }
    elseif ($p.ExitCode -ne 0) { Stop-Rescue ("Tailscale installer failed with exit code {0}. See {1}" -f $p.ExitCode, $msiLog) 34 }
    $script:State['tailscaleInstalledByUs'] = $true
    Save-State
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue

    $exe = Get-TailscaleExe
    if (-not $exe) { Stop-Rescue 'Tailscale reported success but tailscale.exe was not found.' 34 }
    Write-RLog 'OK' 'Tailscale installed'
    return $exe
}

function Wait-TailscaleDaemon([string]$Exe) {
    $svc = Get-Service -Name 'Tailscale' -ErrorAction SilentlyContinue
    if (-not $svc) { Stop-Rescue 'The Tailscale service does not exist.' 35 }
    try { Set-Service -Name Tailscale -StartupType Automatic -ErrorAction SilentlyContinue } catch { }
    if ($svc.Status -ne 'Running') { try { Start-Service -Name Tailscale -ErrorAction Stop } catch { Stop-Rescue ("Could not start the Tailscale service: " + $_.Exception.Message) 35 } }
    for ($i = 0; $i -lt 45; $i++) {
        $st = Get-TailscaleStatus $Exe
        if ($st) { return $st }
        Start-Sleep -Seconds 2
    }
    Stop-Rescue 'The Tailscale service is running but is not answering.' 35
}

function Read-AuthKey {
    if ($AuthKeyFile) {
        if (-not (Test-Path -LiteralPath $AuthKeyFile)) { Stop-Rescue ("Key file not found: " + $AuthKeyFile) 36 }
        return ((Get-Content -LiteralPath $AuthKeyFile -Raw).Trim())
    }
    Write-Host ''
    Write-Host '   Paste the one-time Tailscale key you were sent (it starts with tskey-), then press Enter.' -ForegroundColor White
    Write-Host '   Nothing will show while you paste - that is normal. Press Enter on an empty line to use a login link instead.' -ForegroundColor White
    $sec = Read-Host -Prompt '   Key' -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { return ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)).Trim() }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Get-TsHostName {
    $n = ("rescue-" + $env:COMPUTERNAME).ToLower() -replace '[^a-z0-9-]', '-'
    if ($n.Length -gt 40) { $n = $n.Substring(0, 40) }
    return $n.Trim('-')
}

function Connect-Tailscale([string]$Exe) {
    Write-RLog 'STEP' 'Joining the helper''s Tailscale network'
    $st = Wait-TailscaleDaemon $Exe
    if ($st.BackendState -eq 'Running') {
        if (Get-StateBool 'tailscaleJoinedByUs') { Write-RLog 'OK' 'Already connected to the tailnet from an earlier run'; return }
        $tn = Get-Prop (Get-Prop $st 'CurrentTailnet') 'Name' 'unknown'
        Write-RLog 'WARN' ("Tailscale on this PC is ALREADY signed in (tailnet: {0}). It was left untouched. The helper must be given access to this device from that tailnet, or sign out of Tailscale and run this again." -f $tn)
        $script:State['tailscalePreexistingLogin'] = $true
        Save-State
        return
    }

    $key = Read-AuthKey
    $hostName = Get-TsHostName
    $common = @('up', '--unattended', ('--hostname=' + $hostName), '--accept-dns=false', '--accept-routes=false', '--reset')
    $keyFile = Join-Path $script:Dir 'ts-key.tmp'

    if ($key) {
        if ($key -notmatch '^tskey-[A-Za-z0-9_-]{10,}$') { Stop-Rescue 'That does not look like a Tailscale key (it should start with tskey-). Nothing was changed on Tailscale.' 36 }
        [void]$script:Secrets.Add($key)
        $ok = $false
        try {
            [IO.File]::WriteAllText($keyFile, $key, (New-Object System.Text.UTF8Encoding($false)))
            $r = Invoke-Native $Exe ($common + @(('--auth-key=file:' + $keyFile), '--timeout=120s'))
            $ok = ($r.ExitCode -eq 0)
            if (-not $ok) {
                Write-RLog 'LOG' 'Key-file form did not work; trying the direct form once.'
                $r = Invoke-Native $Exe ($common + @(('--auth-key=' + $key), '--timeout=120s'))
                $ok = ($r.ExitCode -eq 0)
            }
            if (-not $ok) {
                $why = (($r.Output -join ' ')); if ($why.Length -gt 300) { $why = $why.Substring(0, 300) }
                Stop-Rescue ("Tailscale refused to sign in: {0}  (The key may be expired, already used, or mistyped - ask the helper for a new one.)" -f (Hide-Secrets $why)) 37
            }
        } finally {
            if (Test-Path -LiteralPath $keyFile) {
                try { [IO.File]::WriteAllBytes($keyFile, (New-Object byte[] 256)) } catch { }
                Remove-Item -LiteralPath $keyFile -Force -ErrorAction SilentlyContinue
            }
            $key = $null
        }
    } else {
        Write-RLog 'INFO' 'No key entered - using a login link instead.'
        $outF = Join-Path $script:Dir 'ts-up.out'; $errF = Join-Path $script:Dir 'ts-up.err'
        Remove-Item -LiteralPath $outF, $errF -Force -ErrorAction SilentlyContinue
        $p = Start-Process -FilePath $Exe -ArgumentList $common -PassThru -WindowStyle Hidden -RedirectStandardOutput $outF -RedirectStandardError $errF
        $url = $null
        for ($i = 0; $i -lt 60 -and -not $url; $i++) {
            Start-Sleep -Seconds 1
            $txt = ''
            foreach ($f in @($outF, $errF)) { if (Test-Path -LiteralPath $f) { $txt += (Get-Content -LiteralPath $f -Raw -ErrorAction SilentlyContinue) } }
            if ($txt -match '(https://login\.tailscale\.com/a/[A-Za-z0-9]+)') { $url = $Matches[1] }
        }
        if (-not $url) {
            try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch { }
            Stop-Rescue 'Tailscale did not produce a login link.' 37
        }
        Write-Host ''
        Write-Host '   ============================================================' -ForegroundColor Yellow
        Write-Host '   SEND THIS LINK TO YOUR HELPER - they must open it and approve:' -ForegroundColor Yellow
        Write-Host ('   ' + $url) -ForegroundColor White
        Write-Host '   (Keep this window open. Waiting up to 15 minutes.)' -ForegroundColor Yellow
        Write-Host '   ============================================================' -ForegroundColor Yellow
        Write-RLog 'LOG' ('Login link issued: ' + $url)
        $deadline = (Get-Date).AddMinutes(15)
        $joined = $false
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 5
            $s2 = Get-TailscaleStatus $Exe
            if ($s2 -and $s2.BackendState -eq 'Running') { $joined = $true; break }
        }
        try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch { }
        Remove-Item -LiteralPath $outF, $errF -Force -ErrorAction SilentlyContinue
        if (-not $joined) { Stop-Rescue 'The login link was not approved within 15 minutes. Run the command again for a new link.' 37 }
    }

    $script:State['tailscaleJoinedByUs'] = $true
    $script:State['tsHostName'] = $hostName
    Save-State
    Write-RLog 'OK' ("Joined the tailnet as '{0}' (unattended mode on: it stays connected without anyone logged in)" -f $hostName)
}

# ----------------------------------------------------------------------------------------------
# Verification + summary
# ----------------------------------------------------------------------------------------------
function Test-Setup([string]$TsExe) {
    Write-RLog 'STEP' 'Verifying'
    $res = [ordered]@{ Sshd = $false; Listening = $false; ConfigOk = $false; FirewallRule = $false; Tailscale = $false; Ip = $null; DnsName = $null; ReachableOverTailnet = $false }

    $svc = Get-Service sshd -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        $mode = (Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue).StartMode
        $res.Sshd = $true
        if ($mode -eq 'Auto') { Write-RLog 'OK' 'sshd is Running, start type Automatic' } else { Write-RLog 'WARN' ("sshd is Running but start type is {0}" -f $mode) }
    } else { Write-RLog 'ERR' 'sshd is not running' }

    try {
        $l = Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction Stop
        if ($l) { $res.Listening = $true; Write-RLog 'OK' 'Something is listening on TCP port 22' }
    } catch {
        $ns = Invoke-Native 'netstat.exe' @('-ano', '-p', 'TCP') -Quiet
        if ($ns.Output -match ':22\s+\S+\s+LISTENING') { $res.Listening = $true; Write-RLog 'OK' 'Something is listening on TCP port 22' }
    }
    if (-not $res.Listening) { Write-RLog 'ERR' 'Nothing is listening on TCP port 22' }

    $sshd = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
    if (Test-Path -LiteralPath $sshd) {
        $t = Invoke-Native $sshd @('-t') -Quiet
        if ($t.ExitCode -eq 0) { $res.ConfigOk = $true; Write-RLog 'OK' 'sshd_config passes the syntax test' } else { Write-RLog 'WARN' ('sshd_config test reported: ' + ($t.Output -join ' ')) }
    }

    $fw = Get-NetFirewallRule -Name $script:FwRuleName -ErrorAction SilentlyContinue
    if ($fw -and $fw.Enabled -eq 'True') { $res.FirewallRule = $true; Write-RLog 'OK' 'Firewall rule (SSH from Tailscale only) is active' } else { Write-RLog 'ERR' 'Firewall rule is missing or disabled' }

    # Anything else that opens 22 to every address?
    try {
        $open = @()
        foreach ($r in (Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop)) {
            if ($r.Name -eq $script:FwRuleName) { continue }
            $pf = $r | Get-NetFirewallPortFilter
            if ($pf.Protocol -eq 'TCP' -and ($pf.LocalPort -contains '22')) {
                $af = $r | Get-NetFirewallAddressFilter
                if ($af.RemoteAddress -contains 'Any') { $open += $r.DisplayName }
            }
        }
        if ($open.Count -gt 0) { Write-RLog 'WARN' ("Other firewall rule(s) also allow SSH from any address: {0}" -f ($open -join '; ')) }
    } catch { }

    if ($TsExe) {
        $st = Get-TailscaleStatus $TsExe
        if ($st -and $st.BackendState -eq 'Running') {
            $res.Tailscale = $true
            for ($i = 0; $i -lt 15 -and -not $res.Ip; $i++) { $res.Ip = Get-TailscaleIPv4 $TsExe; if (-not $res.Ip) { Start-Sleep -Seconds 2 } }
            $res.DnsName = (Get-Prop (Get-Prop $st 'Self') 'DNSName' '') -replace '\.$', ''
            if ($res.Ip) {
                Write-RLog 'OK' ("Tailscale is connected, address {0}" -f $res.Ip)
                $res.ReachableOverTailnet = Test-TcpPort $res.Ip 22 4000
                if ($res.ReachableOverTailnet) { Write-RLog 'OK' 'SSH answers on the Tailscale address' } else { Write-RLog 'WARN' 'SSH did not answer on the Tailscale address from this PC itself' }
            } else { Write-RLog 'ERR' 'Tailscale is connected but has no address yet' }
        } else {
            $bs = $(if ($st) { $st.BackendState } else { 'not responding' })
            Write-RLog 'ERR' ("Tailscale is not connected (state: {0})" -f $bs)
        }
    }
    return $res
}

function Get-HostKeyFingerprint {
    try {
        $pub = Join-Path $env:ProgramData 'ssh\ssh_host_ed25519_key.pub'
        $kg  = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
        if ((Test-Path -LiteralPath $pub) -and (Test-Path -LiteralPath $kg)) {
            $r = Invoke-Native $kg @('-lf', $pub) -Quiet
            if ($r.ExitCode -eq 0) { foreach ($l in $r.Output) { if ($l -match '(SHA256:\S+)') { return $Matches[1] } } }
        }
    } catch { }
    return $null
}

function Show-Summary($R) {
    $user = $env:USERNAME
    $good = $R.Sshd -and $R.Listening -and $R.FirewallRule -and $R.Tailscale -and $R.Ip
    $lines = @()
    $lines += '============================================================'
    $lines += $(if ($good) { ' RESCUE SETUP COMPLETE' } else { ' RESCUE SETUP INCOMPLETE - see the [FAIL] lines above' })
    $lines += '============================================================'
    $lines += (" Windows user     : {0}\{1}" -f $env:USERDOMAIN, $user)
    $lines += (" Computer name    : {0}" -f $env:COMPUTERNAME)
    $lines += (" Tailscale IPv4   : {0}" -f $(if ($R.Ip) { $R.Ip } else { '(none)' }))
    if ($R.DnsName) { $lines += (" Tailscale name   : {0}" -f $R.DnsName) }
    $fp = Get-HostKeyFingerprint
    if ($fp) { $lines += (" SSH host key     : {0}  (ed25519)" -f $fp) }
    $lines += (" SSH service      : {0}" -f $(if ($R.Sshd -and $R.Listening) { 'running, listening on port 22' } else { 'NOT OK' }))
    $lines += (" Firewall         : {0}" -f $(if ($R.FirewallRule) { 'SSH allowed from Tailscale addresses only' } else { 'NOT OK' }))
    if ($script:RebootNeeded) { $lines += ' RESTART REQUIRED: restart Windows, then run the same command again.' }
    foreach ($w in $script:Warnings) { $lines += (" Note: " + $w) }
    $lines += (" Log file        : {0}" -f $script:LogFile)
    $lines += (" Remove it later : {0}" -f (Join-Path $script:Dir 'uninstall.cmd'))
    $lines += ''
    $lines += $(if ($good) { ' >> Tell your helper:  RESCUE-READY {0}\{1} {2}' -f $env:COMPUTERNAME, $user, $R.Ip } else { ' >> Tell your helper what the [FAIL] lines say, or send the log file.' })
    $lines += '============================================================'
    Write-Host ''
    foreach ($l in $lines) { Write-Host $l -ForegroundColor $(if ($good) { 'Green' } else { 'Yellow' }) }
    $summaryFile = Join-Path $script:Dir 'last-summary.txt'
    try { ($lines | ForEach-Object { Hide-Secrets $_ }) | Set-Content -LiteralPath $summaryFile -Encoding ASCII } catch { }
    foreach ($l in $lines) { Write-RLog 'LOG' $l }
    if ($good) {
        try { (' RESCUE-READY {0}\{1} {2}' -f $env:COMPUTERNAME, $user, $R.Ip).Trim() | & clip.exe; Write-Host ' (The RESCUE-READY line was copied to the clipboard.)' -ForegroundColor DarkGray } catch { }
    }
    return $good
}

function Write-Uninstaller {
    $cmd = Join-Path $script:Dir 'uninstall.cmd'
    $body = "@echo off`r`nnet session >nul 2>&1 || (echo Run this from an Administrator Command Prompt. & exit /b 10)`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"%ProgramData%\RescueSupport\rescue.ps1`" -Uninstall %*`r`n"
    [IO.File]::WriteAllText($cmd, $body, [Text.Encoding]::ASCII)
}

# ----------------------------------------------------------------------------------------------
# Uninstall
# ----------------------------------------------------------------------------------------------
function Invoke-Uninstall {
    Write-RLog 'STEP' 'Removing Rescue Support'
    if (-not (Test-IsAdmin)) { Stop-Rescue 'Run this from an Administrator Command Prompt.' 10 }
    Load-State
    $hasState = $script:State.Count -gt 0
    if (-not $hasState) { Write-RLog 'WARN' 'No install record found. Only the firewall rule and the marked SSH key will be removed; sshd and Tailscale are not touched.' }

    if (-not $Yes) {
        Write-Host ''
        Write-Host '   This will remove the helper''s SSH key and firewall rule, and undo what the installer added' -ForegroundColor White
        Write-Host '   (OpenSSH Server / Tailscale are removed only if this tool installed them).' -ForegroundColor White
        $a = Read-Host -Prompt '   Type Y and press Enter to continue'
        if ($a -notmatch '^[Yy]') { Write-RLog 'INFO' 'Cancelled. Nothing was changed.'; return $true }
    }
    $failed = $false

    # 1. SSH key lines marked rescue-support
    $files = New-Object System.Collections.ArrayList
    if ($script:State.Contains('keyFile') -and $script:State['keyFile']) { [void]$files.Add($script:State['keyFile']) }
    foreach ($f in @((Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'), (Join-Path $env:USERPROFILE '.ssh\authorized_keys'))) { if ($files -notcontains $f) { [void]$files.Add($f) } }
    foreach ($f in $files) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        try {
            $raw = [IO.File]::ReadAllText($f)
            $keep = @(($raw -split "`r?`n") | Where-Object { $_.Trim() -ne '' -and $_ -notmatch ('\s' + [regex]::Escape($script:KeyMarker) + '\s*$') })
            $removed = (@(($raw -split "`r?`n") | Where-Object { $_.Trim() -ne '' }).Count) - $keep.Count
            if ($removed -gt 0) {
                if ($keep.Count -eq 0 -and $script:State['keyFile'] -eq $f -and (Get-StateBool 'keyFileCreated')) { Remove-Item -LiteralPath $f -Force; Write-RLog 'OK' ("Removed {0} (it only held the helper key)" -f $f) }
                else { [IO.File]::WriteAllText($f, (($keep -join "`r`n") + $(if ($keep.Count) { "`r`n" } else { '' })), (New-Object System.Text.UTF8Encoding($false))); Write-RLog 'OK' ("Removed the helper key from {0} (other keys kept)" -f $f) }
            }
        } catch { $failed = $true; Write-RLog 'ERR' ("Could not clean {0}: {1}" -f $f, $_.Exception.Message) }
    }

    # 2. Firewall
    try {
        if (Get-NetFirewallRule -Name $script:FwRuleName -ErrorAction SilentlyContinue) { Remove-NetFirewallRule -Name $script:FwRuleName; Write-RLog 'OK' 'Removed the Tailscale-only SSH firewall rule' }
        if (Get-StateBool 'builtinRuleDisabledByUs') {
            if (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue) { Enable-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' }
            Write-RLog 'OK' 'Restored the built-in OpenSSH firewall rule'
        }
    } catch { $failed = $true; Write-RLog 'ERR' ("Firewall cleanup failed: " + $_.Exception.Message) }

    # 3. Tailscale
    if ($hasState) {
        $exe = Get-TailscaleExe
        if ($exe -and (Get-StateBool 'tailscaleJoinedByUs')) {
            $r = Invoke-Native $exe @('logout')
            if ($r.ExitCode -eq 0) { Write-RLog 'OK' 'Signed out of Tailscale (the helper should also delete this device in their admin console)' } else { Write-RLog 'WARN' 'Tailscale logout reported a problem; the helper can remove the device in their admin console.' }
        }
        if (Get-StateBool 'tailscaleInstalledByUs') {
            $code = Find-TailscaleProductCode
            if ($code) {
                $p = Start-Process msiexec.exe -ArgumentList @('/x', $code, '/qn', '/norestart') -Wait -PassThru
                if ($p.ExitCode -in 0, 3010) { Write-RLog 'OK' 'Uninstalled Tailscale' } else { $failed = $true; Write-RLog 'ERR' ("Tailscale uninstall exit code {0}" -f $p.ExitCode) }
            } else { Write-RLog 'WARN' 'Tailscale was installed by this tool but no uninstall entry was found. Remove it from Settings > Apps.' }
        } elseif ($exe) { Write-RLog 'INFO' 'Tailscale was already on this PC before; the program is left installed.' }
    }

    # 4. OpenSSH
    if ($hasState) {
        try {
            $svc = Get-Service sshd -ErrorAction SilentlyContinue
            if ($svc) {
                if (Get-StateBool 'sshdInstalledByUs') {
                    if ($svc.Status -eq 'Running') { Stop-Service sshd -Force }
                    $cap = $script:CapName; $c2 = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1; if ($c2) { $cap = $c2.Name }
                    $res = Remove-WindowsCapability -Online -Name $cap
                    if ($res -and (Get-Prop $res 'RestartNeeded' $false)) { $script:RebootNeeded = $true }
                    Write-RLog 'OK' 'Removed the OpenSSH Server optional feature'
                } else {
                    $mode = $script:State['sshdPrevStartMode']
                    $map = @{ 'Auto' = 'Automatic'; 'Manual' = 'Manual'; 'Disabled' = 'Disabled' }
                    if ($mode -and $map.ContainsKey([string]$mode)) { Set-Service sshd -StartupType $map[[string]$mode] }
                    if ($script:State.Contains('sshdPrevRunning') -and -not $script:State['sshdPrevRunning'] -and $svc.Status -eq 'Running') { Stop-Service sshd -Force }
                    Write-RLog 'OK' 'OpenSSH Server was already installed before; its start type and state were restored'
                }
            }
        } catch { $failed = $true; Write-RLog 'ERR' ("OpenSSH cleanup failed: " + $_.Exception.Message) }
    }

    # 5. Our own files (logs are kept for troubleshooting)
    foreach ($n in @('state.json', 'rescue.ps1', 'uninstall.cmd', 'last-summary.txt', 'ts-key.tmp', 'ts-up.out', 'ts-up.err')) { Remove-Item -LiteralPath (Join-Path $script:Dir $n) -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath (Join-Path $script:Dir 'download') -Recurse -Force -ErrorAction SilentlyContinue
    Write-RLog 'OK' ("Removed Rescue Support files (logs kept in {0})" -f $script:Dir)
    if ($script:RebootNeeded) { Write-RLog 'WARN' 'Restart Windows to finish removing the OpenSSH feature.' }
    Write-Host ''
    Write-Host $(if ($failed) { '   Removal finished WITH ERRORS - see above.' } else { '   Removal complete.' }) -ForegroundColor $(if ($failed) { 'Yellow' } else { 'Green' })
    return (-not $failed)
}

# ----------------------------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------------------------
function Invoke-Main {
    try {
        Write-Host ''
        Write-Host ("Rescue Support {0}" -f $script:Version) -ForegroundColor Cyan
        if (-not (Test-IsAdmin)) { Stop-Rescue 'This window is not elevated. Open "Command Prompt" with Run as administrator and try again.' 10 }
        Initialize-WorkDir
        Load-State

        if ($Uninstall) { if (Invoke-Uninstall) { return 0 } else { return 1 } }

        if ($Status) {
            Write-RLog 'STEP' 'Status (nothing is changed)'
            $exe = Get-TailscaleExe
            [void](Test-Setup $exe)
            $keys = $script:State['keyFile']; if ($keys) { Write-RLog 'INFO' ("Helper key file: " + $keys) }
            Write-RLog 'INFO' ("Recorded: sshd installed by this tool = {0}; Tailscale installed by this tool = {1}; joined by this tool = {2}" -f (Get-StateBool 'sshdInstalledByUs'), (Get-StateBool 'tailscaleInstalledByUs'), (Get-StateBool 'tailscaleJoinedByUs'))
            return 0
        }

        Test-Preflight
        if ($CheckOnly) { Write-RLog 'OK' 'Pre-flight checks passed. Nothing was changed.'; return 0 }

        if (-not $Yes) {
            Write-Host ''
            Write-Host '   This will let a trusted helper connect to THIS computer over an encrypted Tailscale link:' -ForegroundColor White
            Write-Host '     - install Windows OpenSSH Server and Tailscale (from Microsoft / tailscale.com)' -ForegroundColor White
            Write-Host '     - allow SSH only from Tailscale addresses; the helper still needs your Windows password or their SSH key' -ForegroundColor White
            Write-Host '     - remove everything later with:  C:\ProgramData\RescueSupport\uninstall.cmd' -ForegroundColor White
            $a = Read-Host -Prompt '   Type Y and press Enter to allow this'
            if ($a -notmatch '^[Yy]') { Write-RLog 'INFO' 'Cancelled by the user. Nothing was changed.'; return 0 }
        }
        Write-RLog 'LOG' 'User confirmed.'

        Install-OpenSshServer
        Add-HelperKey
        Set-SshFirewall
        $ts = Install-Tailscale
        Connect-Tailscale $ts
        Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $script:Dir 'rescue.ps1') -Force -ErrorAction SilentlyContinue
        Write-Uninstaller
        Save-State

        $r = Test-Setup $ts
        $ok = Show-Summary $r
        if ($script:RebootNeeded) { return 3010 }
        if ($ok) { return 0 } else { return 1 }
    } catch {
        if ($_.Exception.Data.Contains('RescueCode')) {
            $rc = [int]$_.Exception.Data['RescueCode']
            Write-RLog 'ERR' $_.Exception.Message
            Write-Host ''
            Write-Host ("   Stopped: " + (Hide-Secrets $_.Exception.Message)) -ForegroundColor Red
            if ($script:LogFile) { Write-Host ("   Log: " + $script:LogFile) -ForegroundColor DarkGray }
            return $rc
        }
        Write-RLog 'ERR' ("Unexpected error: " + $_.Exception.Message)
        Write-RLog 'LOG' ($_ | Out-String)
        Write-Host ''
        Write-Host ("   Unexpected error: " + (Hide-Secrets $_.Exception.Message)) -ForegroundColor Red
        if ($script:LogFile) { Write-Host ("   Log: " + $script:LogFile) -ForegroundColor DarkGray }
        return 99
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $code = Invoke-Main
    exit $code
}
