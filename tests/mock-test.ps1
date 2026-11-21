# Logic tests for rescue.ps1 under PowerShell 7 on Linux with fake Windows cmdlets.
# NOT a Windows test: it proves control flow, idempotence, failure codes, secret handling.
param([string]$Script = (Join-Path $PSScriptRoot '..\docs\rescue.ps1'), [string]$Work)
$ErrorActionPreference = 'Stop'
$Script = (Resolve-Path ($Script -replace '\\', '/')).Path
$root = Split-Path $PSScriptRoot -Parent
$Work = Join-Path $Work 'mock'
if (Test-Path $Work) { Remove-Item $Work -Recurse -Force }
New-Item -ItemType Directory -Path $Work | Out-Null

$GoodKey = 'tskey-auth-kTESTGOODKEY1234-abcdefghijklmnopqrstuvwxyz0123'
$BadKey  = 'tskey-auth-kTESTBADKEY99999-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'
$env:FAKE_GOOD_KEY = $GoodKey
$env:PATH = (Join-Path $root 'tests/fakebin') + [IO.Path]::PathSeparator + $env:PATH

$global:pass = 0; $global:fail = 0
function Assert($cond, $msg) { if ($cond) { $global:pass++; Write-Host "  PASS  $msg" -ForegroundColor Green } else { $global:fail++; Write-Host "  FAIL  $msg" -ForegroundColor Red } }

function New-Env([string]$Name) {
    $d = Join-Path $Work $Name
    New-Item -ItemType Directory -Path $d, "$d/pd", "$d/pd/ssh", "$d/pf", "$d/home", "$d/ts" -Force | Out-Null
    $env:ProgramData = "$d/pd"; $env:ProgramFiles = "$d/pf"; ${env:ProgramFiles(x86)} = "$d/pf86"
    $env:FAKE_PROGRAMFILES = "$d/pf"; $env:FAKE_TS_STATE = "$d/ts"; $env:USERPROFILE = "$d/home"
    $env:SystemRoot = "$d/win"; $env:COMPUTERNAME = 'TESTPC'; $env:USERNAME = 'friend'; $env:USERDOMAIN = 'TESTPC'
    $env:PROCESSOR_ARCHITECTURE = 'AMD64'; $env:PROCESSOR_ARCHITEW6432 = $null
    $keyfile = "$d/key.txt"
    $global:Fake = @{
        admin = $true; build = 19045; ptype = 1; net = $true
        capState = 'NotPresent'; capAddFail = $false; capListFail = $false; capAdded = 0
        svc = @{}; fw = @{}; calls = New-Object System.Collections.ArrayList; sigOk = $true
        builtinRule = $true; dir = $d; msiExit = 0; gate = 'ok'; gateCalls = (New-Object System.Collections.ArrayList)
    }
    $script:Dir = Join-Path $env:ProgramData 'RescueSupport'
    $script:StateFile = Join-Path $script:Dir 'state.json'
    $script:State = [ordered]@{}; $script:RebootNeeded = $false
    $script:Warnings = New-Object System.Collections.ArrayList; $script:Secrets = New-Object System.Collections.ArrayList
    Remove-Item "$d/ts/*" -Force -ErrorAction SilentlyContinue
    return $d
}

$env:ProgramData = Join-Path $Work 'boot'
# ---- load the real script (functions only), then override Windows-only things ----
. $Script
function Test-IsAdmin { return $global:Fake.admin }
function Get-CurrentSid { 'S-1-5-21-1-2-3-1001' }
function Test-TcpPort($HostName, $Port, $TimeoutMs) { if ($HostName -match '^100\.') { return $global:Fake.sshReach -ne $false }; return $global:Fake.net }
function Get-CimInstance { param([Parameter(Position = 0)]$ClassName, $Filter, $Namespace)
    switch ($ClassName) {
        'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Microsoft Windows 10 Pro'; BuildNumber = "$($global:Fake.build)"; OSArchitecture = '64-bit'; ProductType = $global:Fake.ptype } }
        'Win32_Service' { if ($global:Fake.svc.ContainsKey('sshd')) { [pscustomobject]@{ StartMode = $global:Fake.svc['sshd'].Start } } }
    } }
function Get-WindowsCapability { param([switch]$Online, $Name, $ErrorAction)
    if ($global:Fake.capListFail) { throw 'The operation failed. 0x800f0954' }
    [pscustomobject]@{ Name = 'OpenSSH.Server~~~~0.0.1.0'; State = $global:Fake.capState } }
function Add-WindowsCapability { param([switch]$Online, $Name, $ErrorAction)
    $global:Fake.capAdded++
    if ($global:Fake.capAddFail) { throw 'Add-WindowsCapability failed. Error code = 0x800f0954' }
    $global:Fake.capState = 'Installed'
    $global:Fake.svc['sshd'] = [pscustomobject]@{ Name = 'sshd'; Status = 'Stopped'; Start = 'Manual' }
    [IO.File]::WriteAllText((Join-Path $env:ProgramData 'ssh/sshd_config'), "Port 22`nMatch Group administrators`n       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys`n")
    $global:Fake.fw['OpenSSH-Server-In-TCP'] = [pscustomobject]@{ Name = 'OpenSSH-Server-In-TCP'; DisplayName = 'OpenSSH Server'; Enabled = 'True' }
    [pscustomobject]@{ RestartNeeded = $false } }
function Remove-WindowsCapability { param([switch]$Online, $Name) $global:Fake.capState = 'NotPresent'; $global:Fake.svc.Remove('sshd'); [void]$global:Fake.calls.Add('RemoveCap'); [pscustomobject]@{ RestartNeeded = $false } }
function Get-Service { param([Parameter(Position = 0)]$Name)
    if ($Name -eq 'Tailscale') { if (Test-Path (Join-Path $env:ProgramFiles 'Tailscale')) { return [pscustomobject]@{ Name = 'Tailscale'; Status = 'Running' } } else { return $null } }
    if ($global:Fake.svc.ContainsKey($Name)) { return $global:Fake.svc[$Name] } else { return $null } }
function Set-Service { param($Name, $StartupType, $ErrorAction)
    if ($global:Fake.svc.ContainsKey($Name)) { $global:Fake.svc[$Name].Start = $(if ($StartupType -eq 'Automatic') { 'Auto' } else { "$StartupType" }) } }
function Start-Service { param($Name, $ErrorAction) $global:Fake.svc[$Name].Status = 'Running' }
function Stop-Service { param($Name, [switch]$Force) $global:Fake.svc[$Name].Status = 'Stopped' }
function Get-NetFirewallRule { param($Name, $Direction, $Enabled, $Action, $ErrorAction)
    if ($Name) { if ($global:Fake.fw.ContainsKey($Name)) { return $global:Fake.fw[$Name] } else { return $null } }
    return @($global:Fake.fw.Values) }
function New-NetFirewallRule { param($Name, $DisplayName, $Description, $Direction, $Action, $Protocol, $LocalPort, $RemoteAddress, $Profile, $Enabled)
    $global:Fake.fw[$Name] = [pscustomobject]@{ Name = $Name; DisplayName = $DisplayName; Enabled = 'True'; Remote = $RemoteAddress; Port = $LocalPort }
    [void]$global:Fake.calls.Add("NewFw:${Name}:$($RemoteAddress -join ',')") }
function Enable-NetFirewallRule { param($Name) $global:Fake.fw[$Name].Enabled = 'True' }
function Disable-NetFirewallRule { param($Name) $global:Fake.fw[$Name].Enabled = 'False'; [void]$global:Fake.calls.Add("DisableFw:$Name") }
function Remove-NetFirewallRule { param($Name) $global:Fake.fw.Remove($Name); [void]$global:Fake.calls.Add("RemoveFw:$Name") }
function Get-NetFirewallPortFilter { param([Parameter(ValueFromPipeline)]$In) process { [pscustomobject]@{ Protocol = 'TCP'; LocalPort = @('22') } } }
function Get-NetFirewallAddressFilter { param([Parameter(ValueFromPipeline)]$In) process { [pscustomobject]@{ RemoteAddress = @($In.Remote) } } }
function Get-NetTCPConnection { param($LocalPort, $State, $ErrorAction) [pscustomobject]@{ LocalPort = 22 } }
$script:msiCache = Join-Path $Work 'cached.msi'
function Invoke-WebRequest {
    param([switch]$UseBasicParsing, $Uri, $OutFile, $TimeoutSec)
    if ($Uri -match '\.msi$' -and $OutFile) {
        if (-not (Test-Path $script:msiCache)) { Write-Host "  (downloading real MSI once from $Uri)"; Microsoft.PowerShell.Utility\Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $script:msiCache -TimeoutSec 600 }
        Copy-Item $script:msiCache $OutFile -Force; return
    }
    Microsoft.PowerShell.Utility\Invoke-WebRequest -UseBasicParsing -Uri $Uri -TimeoutSec $TimeoutSec
}
function Find-TailscaleProductCode { if (Test-Path (Join-Path $env:ProgramFiles 'Tailscale')) { '{11111111-2222-3333-4444-555555555555}' } }
function Start-Process { param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru, $WindowStyle, $RedirectStandardOutput, $RedirectStandardError)
    if ($FilePath -eq 'msiexec.exe') { & (Join-Path $root 'tests/fakebin/msiexec.exe') @ArgumentList; return [pscustomobject]@{ ExitCode = [int]$global:Fake.msiExit } }
    throw "unexpected Start-Process $FilePath" }
function Invoke-Gate { param($Path, $Body, $TimeoutSec)
    [void]$global:Fake.gateCalls.Add(@($Path, $Body))
    if ($Path -eq '/redeem') {
        switch ($global:Fake.gate) {
            'ok'   { return [pscustomobject]@{ key = $GoodKey } }
            '404'  { $e = New-Object System.Exception 'not found'; $e | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{ StatusCode = 404 }); throw $e }
            '410'  { $e = New-Object System.Exception 'gone'; $e | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{ StatusCode = 410 }); throw $e }
            default { throw 'The remote name could not be resolved' }
        }
    }
    return [pscustomobject]@{ stored = $true } }
function Get-AuthenticodeSignature { param($LiteralPath)
    [pscustomobject]@{ Status = $(if ($global:Fake.sigOk) { 'Valid' } else { 'HashMismatch' }); SignerCertificate = [pscustomobject]@{ Subject = 'CN=Tailscale Inc., O=Tailscale Inc., L=Toronto, C=CA' } } }

function Do-Run([hashtable]$Params = @{}) {
    $script:Dir = Join-Path $env:ProgramData 'RescueSupport'; $script:StateFile = Join-Path $script:Dir 'state.json'
    $script:Warnings = New-Object System.Collections.ArrayList; $script:RebootNeeded = $false
    $null = $script:Secrets.Clear()
    $Uninstall = [bool]$Params.Uninstall; $Status = [bool]$Params.Status; $CheckOnly = [bool]$Params.CheckOnly
    $Arg1 = $(if ($Params.Arg1) { $Params.Arg1 } else { '' }); $Code = $(if ($Params.Code) { $Params.Code } else { '' }); $Yes = $true; $AuthKeyFile = $(if ($Params.AuthKeyFile) { $Params.AuthKeyFile } else { '' }); $PublicKey = ''
    $buf = New-Object System.Collections.ArrayList
    $res = & { $r = Invoke-Main; $r } 6>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.InformationRecord]) { [void]$buf.Add("$($_.MessageData)") } else { $_ } }
    $code = @($res | Where-Object { $_ -is [int] })[-1]
    $script:lastOut = ($buf -join "`n")
    return $code
}
function AllText([string]$d) { (Get-ChildItem $d -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\.msi$' } | ForEach-Object { Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue }) -join "`n" }

$pubKeyLine = (Get-Content (Join-Path $root 'src/helper_key.pub') -Raw).Trim()
$blob = ($pubKeyLine -split ' ')[1]

Write-Host "`n[1] happy path (fresh PC)" -ForegroundColor Cyan
$d = New-Env 'happy'
Set-Content "$d/key.txt" $GoodKey -NoNewline
$code = Do-Run @{ AuthKeyFile = "$d/key.txt" }
Assert ($code -eq 0) "exit code 0 (got $code)"
if ($code -ne 0) { Write-Host $script:lastOut }
Assert ($Fake.capState -eq 'Installed' -and $Fake.capAdded -eq 1) 'OpenSSH capability installed once'
Assert ($Fake.svc['sshd'].Status -eq 'Running' -and $Fake.svc['sshd'].Start -eq 'Auto') 'sshd Running + Automatic'
Assert ($Fake.fw['RescueSupport-SSH-Tailscale'].Remote -contains '100.64.0.0/10') 'firewall rule limited to 100.64.0.0/10'
Assert ($Fake.fw['OpenSSH-Server-In-TCP'].Enabled -eq 'False') 'built-in any-address rule disabled (we installed sshd)'
$akf = Get-Content "$d/pd/ssh/administrators_authorized_keys" -Raw
Assert ($akf -match [regex]::Escape($blob) -and $akf -match 'rescue-support') 'helper pubkey in administrators_authorized_keys (marked)'
Assert (Test-Path "$d/pf/Tailscale/tailscale.exe") 'tailscale installed via (fake) msiexec'
Assert ((Get-Content "$d/ts/msi.log" -Raw) -match '/qn' -and (Get-Content "$d/ts/msi.log" -Raw) -match 'TS_NOLAUNCH=1') 'msiexec silent + TS_NOLAUNCH'
Assert (Test-Path "$d/ts/up") 'tailscale up succeeded'
$upargs = Get-Content "$d/ts/up-args.log" -Raw
Assert ($upargs -match '--unattended' -and $upargs -match '--accept-dns=false' -and $upargs -match '--auth-key=file:') 'tailscale up: unattended, no DNS change, key via file:'
Assert ($upargs -notmatch 'tskey-') 'secret NOT on tailscale command line'
Assert (-not (Test-Path "$d/pd/RescueSupport/ts-key.tmp")) 'temporary key file deleted'
Assert ($script:lastOut -match 'RESCUE SETUP COMPLETE' -and $script:lastOut -match '100\.101\.102\.103') 'summary shows success + tailscale IP'
Assert ((AllText "$d/pd/RescueSupport") -notmatch 'tskey-auth-kTEST') 'no key in logs/state/summary'
Assert ($script:lastOut -notmatch 'tskey-auth-kTEST') 'no key in console output'
$st = Get-Content "$d/pd/RescueSupport/state.json" -Raw | ConvertFrom-Json
Assert ($st.sshdInstalledByUs -eq $true -and $st.tailscaleInstalledByUs -eq $true -and $st.tailscaleJoinedByUs -eq $true) 'state records what we installed'
Assert (Test-Path "$d/pd/RescueSupport/uninstall.cmd") 'uninstall.cmd written'

Write-Host "`n[2] re-run is idempotent" -ForegroundColor Cyan
$callsBefore = $Fake.calls.Count; $msiBefore = (Get-Content "$d/ts/msi.log").Count
$code = Do-Run @{ AuthKeyFile = "$d/key.txt" }
Assert ($code -eq 0) "exit code 0 (got $code)"
Assert ($Fake.capAdded -eq 1) 'capability not installed again'
Assert ((Get-Content "$d/ts/msi.log").Count -eq $msiBefore) 'tailscale not reinstalled'
$akf2 = Get-Content "$d/pd/ssh/administrators_authorized_keys" -Raw
Assert ((([regex]::Matches($akf2, [regex]::Escape($blob))).Count) -eq 1) 'helper key not duplicated'
Assert ($Fake.calls.Count -eq $callsBefore) 'no further firewall changes'
$st2 = Get-Content "$d/pd/RescueSupport/state.json" -Raw | ConvertFrom-Json
Assert ($st2.sshdInstalledByUs -eq $true) 'ownership flags preserved across runs'

Write-Host "`n[3] status mode changes nothing" -ForegroundColor Cyan
$code = Do-Run @{ Status = $true }
Assert ($code -eq 0 -and $script:lastOut -match 'Tailscale is connected') "status ok (code $code)"

Write-Host "`n[4] uninstall restores everything" -ForegroundColor Cyan
Add-Content "$d/pd/ssh/administrators_authorized_keys" 'ssh-ed25519 AAAAOTHERKEYBLOB someone-else'
$code = Do-Run @{ Uninstall = $true }
Assert ($code -eq 0) "exit code 0 (got $code)"
$akf3 = Get-Content "$d/pd/ssh/administrators_authorized_keys" -Raw
Assert ($akf3 -notmatch [regex]::Escape($blob) -and $akf3 -match 'someone-else') 'our key removed, other key kept'
Assert (-not $Fake.fw.ContainsKey('RescueSupport-SSH-Tailscale')) 'our firewall rule removed'
Assert ($Fake.fw['OpenSSH-Server-In-TCP'].Enabled -eq 'True') 'built-in rule restored'
Assert ($Fake.capState -eq 'NotPresent') 'OpenSSH capability removed (we installed it)'
Assert (-not (Test-Path "$d/pf/Tailscale")) 'tailscale uninstalled'
Assert (-not (Test-Path "$d/ts/up")) 'tailscale logged out'
Assert (-not (Test-Path "$d/pd/RescueSupport/state.json")) 'state removed'

Write-Host "`n[5] pre-existing sshd + tailscale are left alone" -ForegroundColor Cyan
$d = New-Env 'preexisting'
$Fake.capState = 'Installed'; $Fake.svc['sshd'] = [pscustomobject]@{ Name = 'sshd'; Status = 'Stopped'; Start = 'Manual' }
[IO.File]::WriteAllText("$d/pd/ssh/sshd_config", "Match Group administrators`n AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys`n")
[IO.File]::WriteAllText("$d/pd/ssh/administrators_authorized_keys", "ssh-ed25519 AAAAEXISTING owner@box`n")
$Fake.fw['OpenSSH-Server-In-TCP'] = [pscustomobject]@{ Name = 'OpenSSH-Server-In-TCP'; DisplayName = 'OpenSSH'; Enabled = 'True' }
New-Item -ItemType Directory "$d/pf/Tailscale" -Force | Out-Null; Copy-Item (Join-Path $root 'tests/fakebin/tailscale') "$d/pf/Tailscale/tailscale.exe"; chmod +x "$d/pf/Tailscale/tailscale.exe"
New-Item "$d/ts/up" -ItemType File | Out-Null   # already signed in to someone else's tailnet
$code = Do-Run @{}
Assert ($code -eq 0) "exit 0 (got $code)"
Assert ($Fake.capAdded -eq 0) 'did not reinstall sshd'
Assert ($Fake.fw['OpenSSH-Server-In-TCP'].Enabled -eq 'True') 'did not touch pre-existing built-in firewall rule'
Assert ($script:lastOut -match 'ALREADY signed in') 'warns that Tailscale is already signed in; does not re-enrol'
Assert (-not (Test-Path "$d/ts/up-args.log")) 'tailscale up NOT called'
$null = Do-Run @{ Uninstall = $true }
Assert ((Get-Content "$d/pd/ssh/administrators_authorized_keys" -Raw) -match 'AAAAEXISTING') 'existing authorised key kept after uninstall'
Assert ($Fake.capState -eq 'Installed' -and (Test-Path "$d/pf/Tailscale")) 'pre-existing sshd + tailscale still installed after uninstall'
Assert ($Fake.svc['sshd'].Start -eq 'Manual' -and $Fake.svc['sshd'].Status -eq 'Stopped') 'sshd start type/state restored to what it was'
Assert (Test-Path "$d/ts/up") 'we did NOT log the owner out of their own tailnet'

Write-Host "`n[6] failure paths" -ForegroundColor Cyan
$d = New-Env 'f-notadmin'; $Fake.admin = $false
Assert ((Do-Run @{}) -eq 10) 'not elevated -> code 10'
$d = New-Env 'f-oldwin'; $Fake.build = 14393
Assert ((Do-Run @{}) -eq 11) 'Windows build too old -> code 11'
$d = New-Env 'f-offline'; $Fake.net = $false
$c = Do-Run @{}; Assert ($c -eq 12 -and $script:lastOut -match 'No usable internet') 'no internet -> code 12, clear message'
Assert ($Fake.capAdded -eq 0) 'offline: nothing was changed'
$d = New-Env 'f-caplist'; $Fake.capListFail = $true
$c = Do-Run @{}; Assert ($c -eq 20 -and $script:lastOut -match '0x800f0954') "feature listing fails -> code 20 with Windows error ($c)"
$d = New-Env 'f-capadd'; $Fake.capAddFail = $true
$c = Do-Run @{}; Assert ($c -eq 21 -and $script:lastOut -match 'refused to install OpenSSH' -and $script:lastOut -notmatch 'COMPLETE') "optional-feature install fails -> code 21, not reported as success ($c)"
Assert (-not (Test-Path "$d/ts/msi.log")) 'after sshd failure, tailscale untouched'
$d = New-Env 'f-badkeyfmt'; Set-Content "$d/key.txt" 'not-a-key' -NoNewline
$c = Do-Run @{ AuthKeyFile = "$d/key.txt" }; Assert ($c -eq 36) "malformed key rejected locally -> code 36 ($c)"
$d = New-Env 'f-refused'; Set-Content "$d/key.txt" $BadKey -NoNewline
$c = Do-Run @{ AuthKeyFile = "$d/key.txt" }
Assert ($c -eq 37 -and $script:lastOut -match 'refused to sign in') "tailscale rejects key -> code 37 ($c)"
Assert ($script:lastOut -notmatch 'kTESTBADKEY' -and (AllText "$d/pd/RescueSupport") -notmatch 'kTESTBADKEY') 'rejected key redacted from console AND logs'
Assert (-not (Test-Path "$d/pd/RescueSupport/ts-key.tmp")) 'key temp file removed after failure'
$d = New-Env 'f-sig'; $Fake.sigOk = $false
Set-Content "$d/key.txt" $GoodKey -NoNewline
$c = Do-Run @{ AuthKeyFile = "$d/key.txt" }
Assert ($c -eq 33 -and -not (Test-Path "$d/pf/Tailscale")) "bad Authenticode signature -> code 33, nothing installed ($c)"
$d = New-Env 'f-msi'; $Fake.msiExit = 1603; Set-Content "$d/key.txt" $GoodKey -NoNewline
$c = Do-Run @{ AuthKeyFile = "$d/key.txt" }; Assert ($c -eq 34) "msi failure 1603 -> code 34 ($c)"
$d = New-Env 'f-reboot'; $Fake.msiExit = 3010; Set-Content "$d/key.txt" $GoodKey -NoNewline
$c = Do-Run @{ AuthKeyFile = "$d/key.txt" }; Assert ($c -eq 3010 -and $script:lastOut -match 'RESTART REQUIRED') "msi 3010 -> reboot-required reported ($c)"
$d = New-Env 'f-check'
$c = Do-Run @{ CheckOnly = $true }; Assert ($c -eq 0 -and $Fake.capAdded -eq 0 -and $Fake.fw.Count -eq 0) '-CheckOnly passes and changes nothing'

Write-Host "`n[6b] one-time code flow" -ForegroundColor Cyan
$code16 = 'abcdefghij234567'
$d = New-Env 'code-happy'
$c = Do-Run @{ Code = $code16 }
Assert ($c -eq 0 -and (Test-Path "$d/ts/up")) "install with Code: key fetched from gate, tailscale up ok (code $c)"
Assert (-not $script:lastOut -or $script:lastOut -notmatch 'Paste the one-time') 'no key prompt shown when a code is given'
$rep = @($Fake.gateCalls | Where-Object { $_[0] -eq '/report' })[-1]
Assert ($rep -and $rep[1].report.ok -eq $true -and $rep[1].report.ip -eq '100.101.102.103' -and $rep[1].report.user -eq 'friend' -and $rep[1].code -eq $code16) 'success report carries ip, user, code'
Assert (($Fake.gateCalls | ConvertTo-Json -Depth 6) -notmatch 'tskey-') 'key never sent back to the gate'
Assert ((Get-Content "$d/ts/up-args.log" -Raw) -notmatch 'tskey-') 'key not on tailscale command line (code flow)'
Assert ((AllText "$d/pd/RescueSupport") -notmatch 'tskey-auth-kTEST') 'no key in logs (code flow)'
$d = New-Env 'code-404'; $Fake.gate = '404'
$c = Do-Run @{ Code = $code16 }; Assert ($c -eq 36 -and $script:lastOut -match 'unknown or has expired') "expired code -> 36 with clear message ($c)"
$rep = @($Fake.gateCalls | Where-Object { $_[0] -eq '/report' })[-1]; Assert ($rep -and $rep[1].report.ok -eq $false) 'failure is reported to the helper'
$d = New-Env 'code-410'; $Fake.gate = '410'
$c = Do-Run @{ Code = $code16 }; Assert ($c -eq 36 -and $script:lastOut -match 'already used') "used code -> 36 ($c)"
$d = New-Env 'code-down'; $Fake.gate = 'down'
$c = Do-Run @{ Code = $code16 }; Assert ($c -eq 38 -and $script:lastOut -match 'Could not reach') "gate unreachable -> 38 ($c)"
$d = New-Env 'code-bad'
$c = Do-Run @{ Code = 'short' }; Assert ($c -eq 36) "malformed code -> 36 ($c)"
$d = New-Env 'arg1-code'
$c = Do-Run @{ Arg1 = $code16 }; Assert ($c -eq 0 -and (Test-Path "$d/ts/up")) "positional code (r.cmd CODE) works ($c)"
$d = New-Env 'arg1-check'
$c = Do-Run @{ Arg1 = 'check' }; Assert ($c -eq 0 -and $Fake.capAdded -eq 0) 'positional "check" = CheckOnly'
$d = New-Env 'arg1-bad'
$c = Do-Run @{ Arg1 = 'banana' }; Assert ($c -eq 2) "unknown option -> 2 ($c)"
$Fake.gateCalls.Clear(); $d = New-Env 'status-noreport'; $null = Do-Run @{ Status = $true; Code = $code16 }
Assert (@($Fake.gateCalls | Where-Object { $_[0] -eq '/report' }).Count -eq 0) 'status/check/uninstall never report'

Write-Host "`n[7] published files carry no secrets" -ForegroundColor Cyan
$pub = (Get-Content (Join-Path $root 'docs/rescue.ps1') -Raw) + (Get-Content (Join-Path $root 'docs/r') -Raw) + (Get-Content (Join-Path $root 'docs/diag.ps1') -Raw)
Assert ($pub -notmatch 'tskey-[A-Za-z0-9]{8,}') 'no tskey-... literal in published scripts'
Assert ($pub -notmatch 'PRIVATE KEY') 'no private key material'

Write-Host ("`nRESULT: {0} passed, {1} failed" -f $global:pass, $global:fail) -ForegroundColor $(if ($global:fail) { 'Red' } else { 'Green' })
exit $global:fail
