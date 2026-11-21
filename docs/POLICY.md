# Tailscale policy used with Rescue Support

Replace `YOU@example.com` with your login and the subnet with yours. `autogroup:member` excludes tagged devices, which is the point.

```jsonc
{
"tagOwners": { "tag:rescue": ["autogroup:admin"] },
"grants": [
  // Was {"src":["*"],"dst":["*"],"ip":["*"]}: "*" also matches tagged devices. Same access for user-owned devices,
  // subnet routes and exit nodes, but a tag:rescue device can initiate nothing.
  {"src": ["autogroup:member"], "dst": ["autogroup:member", "192.168.20.0/24", "autogroup:internet"], "ip": ["*"]},
  // Only you reach a rescue PC, SSH only.
  {"src": ["YOU@example.com"], "dst": ["tag:rescue"], "ip": ["tcp:22"]},
],
"tests": [
  {"src": "YOU@example.com", "accept": ["tag:rescue:22"], "deny": ["tag:rescue:3389", "tag:rescue:445"]},
  {"src": "tag:rescue", "deny": ["<one of your device IPs>:22"]},
],
}
```
