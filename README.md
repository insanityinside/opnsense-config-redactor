# opnsense-config-redacter

Strips sensitive values from an OPNsense XML configuration backup so it can be shared safely — for filing bug reports, asking for help, or feeding to an AI assistant.

## Requirements

Python 3.11+ (uses `ipaddress.is_global`, which follows current IANA registries from 3.11 onwards). No third-party packages required.

## Usage

```
python3 redact.py <config.xml>
```

Writes output to `<config>-redacted.xml` in the same directory. The original file is not modified.

## What gets redacted

| Element(s) | Replaced with |
|---|---|
| `<password>` | `REDACTED` |
| `<prv>` (certificate private keys) | `REDACTED` |
| `<crt>` (public certificates — contain PII in subject/SAN) | `REDACTED` |
| `<Key>` (IPsec pre-shared keys) | `REDACTED` |
| `<secret>` (RADIUS, TOTP, other auth secrets) | `REDACTED` |
| `<token>` (Cloudflare tunnel JWTs, API tokens) | `REDACTED` |
| `<apikeys>` blocks (non-empty only; `<apikeys/>` untouched) | `REDACTED` |
| `<authorizedkeys>` (SSH public keys) | `REDACTED` |
| `<hwaddr>` (MAC addresses) | `REDACTED` |
| `<ident>`, `<remote_ident>` (VPN peer identities) | `REDACTED` |
| `<host>` (DHCP static mapping hostnames) | `REDACTED` |
| `<domain>` (local/search domain names) | `REDACTED` |
| `<username>` (usernames, including audit-log `root@ip` entries) | `REDACTED` |
| `<id>` (IPsec phase1 local/remote identifier) | `REDACTED` |
| `<hostnames>` (Cloudflare tunnel / ACME hostnames) | `REDACTED` |
| `<zone>` (DNS override zone names) | `REDACTED` |
| `<friendly_name>` (UPnP device name) | `REDACTED` |
| `<audit>` (firewall rule change history) | `REDACTED` |
| `<geoip>` (GeoIP alias settings — URL contains MaxMind licence key) | `REDACTED` |
| `<privkey>` (WireGuard private keys) | `REDACTED` |
| `<pubkey>` (WireGuard public keys — identifying) | `REDACTED` |
| `<enroll_key>` (CrowdSec console enrolment key) | `REDACTED` |
| `<Prefix>`, `<ClusterUUID>` (Zenarmor device identifiers) | `REDACTED` |
| Public IPv4 addresses in `<ipaddr>`, `<ipaddrv6>`, `<gateway>` | `203.0.113.1` / `2001:db8::1` |

## What is intentionally left alone

- **`<descr>` and `<description>` fields** — contain OPNsense system descriptions (tuneable hints, "System Administrator", etc.) that are needed to make the output useful for diagnosis. Personal names in firewall rule comments will remain visible.
- **DNS servers** (`<dnsserver>`) — not sensitive.
- **RFC 1918 / private IP addresses** — non-routable, needed for diagnosing firewall and routing issues.
- **Config structure** — firewall rules, VLANs, routing, interfaces — the whole point of sharing the file.

## Limitations

- Regex-based, not a full XML parser. Preserves original formatting and comments, but assumes well-formed element content (no CDATA sections wrapping sensitive values).
- `<descr>` fields may still contain personal names or hostnames if you used them in firewall rule comments or DHCP labels.
- Does not redact `<name>` elements (used pervasively for interface names, rule names, alias names — too broad to safely blanket-redact).

## License

BSD 2-Clause — see [LICENSE](LICENSE).
