# Rescue Support

A transparent, removable remote-support installer for **Windows 10 x64**. A trusted friend types one short command in an Administrator Command Prompt; the PC then becomes reachable by SSH **only over Tailscale**, for the helper only.

It is not a backdoor: it asks for confirmation, publishes its full source, adds no accounts or passwords, opens nothing on the router, and ships with an uninstaller that undoes exactly what it changed.

## For the person being helped

Open **Command Prompt or PowerShell** (either works; Administrator is not required to start) and type the single line your helper gave you:

```cmd
cmd /c "cd /d %temp%&&curl.exe -fsSL https://crossainthero-lab.github.io/fix/r -o r.cmd&&r.cmd YOURCODE"
```

1. If Windows asks permission (UAC), choose **Yes** (keyboard only: **Alt+Y**, or Left Arrow then Enter). A new window opens and continues there.
2. Read what it says, type `Y`, press Enter.
3. Wait for `RESCUE SETUP COMPLETE`. Nothing needs to be sent: the helper's computer is told automatically (computer name, Windows user name, Tailscale address, result - nothing else).

If it stops with a message, tell your helper what it says. Everything is logged in `C:\ProgramData\RescueSupport`.

**Remove everything later** (Administrator Command Prompt):

```cmd
C:\ProgramData\RescueSupport\uninstall.cmd
```

or: `cmd /c "cd /d %temp%&&curl.exe -fsSL https://crossainthero-lab.github.io/fix/r -o r.cmd&&r.cmd uninstall"`

Other modes: `r.cmd status` (change nothing), `r.cmd check` (pre-flight only). Without a code, the installer asks you to paste a Tailscale key instead.

## For the helper

### One-time Tailscale setup (done once per tailnet)

Policy (Access controls > JSON editor): `tag:rescue` owned by admins; user-owned devices keep their existing access, but tagged devices are no longer a *source* (so a rescue PC can initiate nothing); only you reach `tag:rescue`, on TCP 22. Exact grants, with `tests` that run on every save, are in [`docs/POLICY.md`](docs/POLICY.md). Do not leave a `"src": ["*"]` grant: `*` includes tagged devices.

### Per rescue session

1. Generate an auth key (Settings > Keys): *Reusable* off, *Ephemeral* off, expiry **1 day**, *Tags* `tag:rescue`.
2. Put it in the one-time gate. The key is read from stdin (never argv), encrypted with a fresh random 16-character code, and only that code is printed:
   ```bash
   <paste key on stdin> | CLOUDFLARE_ACCOUNT_ID=... node gate/provision.mjs <kv-namespace-id> 86400
   ```
3. Give your friend the printed code inside the command above.
4. Watch for the PC: `gate/watch.sh CODE` prints `ssh USER@TAILSCALE_IP` and the host-key fingerprint to expect.
5. Afterwards: run the uninstaller, then delete the device in the admin console.

### How the one-time gate works (`gate/`)

A tiny Cloudflare Worker (`rescue-gate`) with one KV namespace. The key is stored AES-GCM-encrypted under a key derived from the code; KV is keyed by the SHA-256 of the code, so neither the code nor the Tailscale key can be read from storage. `POST /redeem` returns the key to whoever presents the code; the PC confirms enrolment with `POST /report`, after which the encrypted key is deleted and the code answers `410`. Entries expire after 24 hours. The Tailscale key itself is single-use, tagged and expires in 1 day. Deploy with `gate/deploy.sh` into a dedicated Cloudflare account.

### Connect from Linux

```bash
ssh WINDOWS_USERNAME@TAILSCALE_IP            # key auth (your public key is installed); falls back to the Windows password
```

Compare the host-key fingerprint with the one reported. The default remote shell is `cmd.exe`; run `powershell` for PowerShell. Microsoft-account PCs: use the local profile name shown by the installer; password login uses the Microsoft-account password (PINs do not work over SSH).

Diagnostics (read-only by default):

```bash
scp src/diag.ps1 USER@IP:C:/Users/USER/
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
| Tailscale (official MSI, SHA-256 + Authenticode checked), joined with `--unattended --accept-dns=false --accept-routes=false` | Logged out; uninstalled (plus its leftover `Tailscale-Process` firewall rule and `C:\ProgramData\Tailscale`) only if this tool installed it. If the PC was already signed in to a tailnet, it is not touched |
| `C:\ProgramData\RescueSupport` (log, state, uninstall.cmd), admin-only ACL | Files removed; logs kept |

`sshd_config` is not edited. Defender, UAC, accounts and passwords are not touched.

## Security notes

- The Tailscale key is never in this repo, the command line, the logs or the state file. It arrives from the one-time gate (or a hidden prompt without a code), is written to an admin-only temp file, passed as `--auth-key=file:...`, and the file is overwritten and deleted. Any `tskey-...` text is redacted from the log.
- `r` verifies `rescue.ps1` against a SHA-256 baked into `r` (shown on screen). Both come from the same host, so this guards against corruption and stale caches; it does not replace reading the script. `SHA256SUMS` lists all published files.
- The `-ExecutionPolicy Bypass` flag applies to that single PowerShell process only; no system policy is changed.

## Exit codes

`0` ok - `2` bad option - `10` not elevated - `11` Windows too old - `12` no internet - `20-23` OpenSSH feature/service problem - `30-35` Tailscale download/signature/install/service problem - `36` code or key rejected - `37` Tailscale refused the key - `38` provisioning service unreachable - `3010` restart required - `99` unexpected (see log).

## Tests

- `tests/parse.ps1`: syntax check (run under Windows PowerShell 5.1 and PowerShell 7).
- `tests/mock-test.ps1` (77 checks): the real installer logic under PowerShell 7 on Linux with fake Windows cmdlets and a fake `tailscale`: happy path, idempotent re-run, uninstall incl. leftovers, pre-existing components, the one-time-code flow, every failure code, secret redaction. It also downloads the real Tailscale MSI and checks it against the published checksum. Mock tests, not a Windows installation.
- **Real Windows (Windows 11 VM, PowerShell 5.1), end to end with the published launcher:** install with a one-time code -> key redeemed -> Tailscale installed and joined as `tag:rescue` -> SSH over the tailnet with key auth -> only TCP 22 reachable, and the rescue node could not initiate connections to other tailnet devices -> uninstall -> firewall rules, programs, adapters, DNS, routes, listening ports and the SHA-256 of `sshd_config`/authorized keys/`hosts` identical to the baseline. Also: failure path with an unknown code, tamper detection in the launcher, `-CheckOnly`, `-Status`, `diag.ps1`.
- **Not run on real Windows:** installing the OpenSSH Server *feature* from scratch (that VM already had it), the UAC self-elevation prompt (the test session was already elevated), and Windows 10 itself.

Rebuild the published files with `./build.sh` (embeds the helper public key, the gate URL and the script hash).
