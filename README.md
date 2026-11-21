# Rescue Support

A transparent, removable remote-support installer for **Windows 10 x64**. A trusted friend types one short command in an Administrator Command Prompt; the PC then becomes reachable by SSH **only over Tailscale**, for the helper only.

It is not a backdoor: it asks for confirmation, publishes its full source, adds no accounts or passwords, opens nothing on the router, and ships with an uninstaller that undoes exactly what it changed.

## For the person being helped

1. Press the Windows key, type `cmd`, press **Ctrl+Shift+Enter**, answer **Yes**. (The window title must say *Administrator*.)
2. Type this and press Enter:

   ```cmd
   cd /d %temp%&&curl.exe -fsSL https://crossainthero-lab.github.io/fix/r -o r.cmd&&r.cmd
   ```
3. Read what it says, type `Y`, press Enter.
4. When asked for the **key**, paste the `tskey-...` text your helper sent you (right-click pastes in Command Prompt; nothing appears while pasting) and press Enter.
5. When it prints `RESCUE SETUP COMPLETE`, send the `RESCUE-READY ...` line to your helper (it is also copied to the clipboard).

No key? Press Enter at the key prompt: it prints a login link instead. Send that link to the helper, who approves it.

**Remove everything later** (Administrator Command Prompt):

```cmd
C:\ProgramData\RescueSupport\uninstall.cmd
```

or, if that folder is gone: `cd /d %temp%&&curl.exe -fsSL https://crossainthero-lab.github.io/fix/r -o r.cmd&&r.cmd uninstall`

Other modes: `r.cmd status` (show state, change nothing), `r.cmd check` (pre-flight only).

## For the helper

### One-time Tailscale setup (owner of the tailnet)

1. **Tag and access rules** (Admin console > Access controls). The rescue PC must not be able to reach your other devices, and only you may reach it:

   ```jsonc
   "tagOwners": { "tag:rescue": ["autogroup:admin"] },
   "acls": [
     // YOUR existing rules stay, but make sure none uses "*" as src, because "*" includes tagged devices.
     // autogroup:member = user-owned devices only (tagged devices are excluded).
     { "action": "accept", "src": ["YOU@example.com"], "dst": ["tag:rescue:22"] }
   ]
   ```
   Tagged devices have no outbound access unless a rule names them as `src`.
2. **Create a key** (Settings > Keys > Generate auth key): *Reusable* **off**, *Ephemeral* **off**, *Pre-approved* on (if device approval is enabled), *Tags* `tag:rescue`, *Expiry* **1 day**. Send the `tskey-auth-...` value over a private channel (not email-to-many, not a repo, not a ticket).
3. After the session: delete the device in the admin console, and revoke the key if unused.

Without an auth key, the installer shows a login link; open it as yourself and approve the device (it joins your tailnet as user-owned, so apply the ACL isolation above first).

### Connect from Linux

```bash
ssh WINDOWS_USERNAME@TAILSCALE_IP            # key auth (your public key is installed); falls back to the Windows password
# first connection: compare the host key with the "SSH host key" line the installer printed
```

Notes: the default remote shell is `cmd.exe`; run `powershell` for PowerShell. Microsoft-account PCs: use the local profile name shown by the installer; if password login is needed, use the Microsoft-account password (PINs do not work over SSH).

Diagnostics (read-only by default):

```bash
scp diag.ps1 USER@IP:C:/Users/USER/
ssh USER@IP 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\USER\diag.ps1 -Hours 72'
# optional, explicit, administrator-initiated:  -SfcVerify  -DismScan  -SfcRepair  -DismRepair
```

The report stays on the PC in `C:\ProgramData\RescueSupport\diag-*.txt`; nothing is uploaded.

## What the installer changes (and how it is reversed)

| Change | Reversed by uninstall |
|---|---|
| OpenSSH Server optional feature, `sshd` Automatic + running | Removed only if this tool installed it; otherwise start type/state restored |
| Firewall rule `RescueSupport-SSH-Tailscale`: TCP 22 from `100.64.0.0/10`, `fd7a:115c:a1e0::/48` only | Deleted |
| Windows' built-in `OpenSSH-Server-In-TCP` rule (allows any address) | Disabled only if this tool installed sshd; re-enabled on uninstall. A pre-existing rule is left alone with a warning |
| Helper public key, line ends with `rescue-support` | Only that line is removed; other keys kept |
| Tailscale (official MSI, SHA-256 + Authenticode checked), joined with `--unattended --accept-dns=false --accept-routes=false` | Logged out; uninstalled only if this tool installed it. If the PC was already signed in to a tailnet, it is not touched |
| `C:\ProgramData\RescueSupport` (log, state, uninstall.cmd), admin-only ACL | Files removed; logs kept |

`sshd_config` is not edited. Defender, UAC, accounts and passwords are not touched.

## Security notes

- The Tailscale key is never in this repo, the command line, the logs or the state file. It is typed at a hidden prompt, written to an admin-only temp file, passed as `--auth-key=file:...`, and the file is overwritten and deleted. Any `tskey-...` text is redacted from the log.
- `r` verifies `rescue.ps1` against a SHA-256 baked into `r` (shown on screen). Both come from the same host, so this guards against corruption and stale caches; it does not replace reading the script. `SHA256SUMS` lists all published files.
- The `-ExecutionPolicy Bypass` flag applies to that single PowerShell process only; no system policy is changed.

## Exit codes

`0` ok - `10` not elevated - `11` Windows too old - `12` no internet - `20-23` OpenSSH feature/service problem - `30-35` Tailscale download/signature/install/service problem - `36-37` key rejected - `3010` restart required - `99` unexpected (see log).

## Tests

- `tests/parse.ps1`: syntax check (run under Windows PowerShell 5.1 and PowerShell 7).
- `tests/mock-test.ps1`: logic tests of the real script under PowerShell 7 with fake Windows cmdlets and a fake `tailscale`: happy path, idempotent re-run, uninstall, pre-existing components, failure codes, secret redaction. It also downloads the real Tailscale MSI and checks it against Tailscale's published checksum. These are **mock** tests, not a Windows installation.
- On a real Windows 11 VM (PowerShell 5.1): both scripts parse; `-CheckOnly`, `-Status` and `diag.ps1` ran; the published launcher ran end to end in `check` mode and rejected a tampered fingerprint; the real Tailscale MSI was downloaded and its SHA-256 and Authenticode signer (`O=Tailscale Inc.`) verified; `Get-WindowsCapability` and the firewall scan were exercised read-only.
- **Not yet run on real Windows:** the actual install and uninstall (OpenSSH feature install, firewall rule creation, key placement, Tailscale MSI install and `tailscale up`). Those paths are covered only by the mock tests above.

Rebuild the published files with `./build.sh` (embeds the helper public key and the script hash).
