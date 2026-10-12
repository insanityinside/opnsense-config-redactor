#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026, Richard Aspden (https://github.com/insanityinside)
"""
OPNsense XML config redacter.
Replaces sensitive configuration values with REDACTED placeholder text,
and replaces public (non-RFC-1918) IP addresses with documentation-range IPs.

Usage: ./redact.py <config.xml>
Output: <config>-redacted.xml
"""

import ipaddress
import os
import re
import sys

REDACTED = 'REDACTED'
GENERIC_IPV4 = '203.0.113.1'  # RFC 5737 TEST-NET-3
GENERIC_IPV6 = '2001:db8::1'  # RFC 3849 documentation prefix

# Sensitive element patterns: (pattern, replacement_string, re_flags)
# Groups: \g<1>=opening tag, \g<2>=content, \g<3>=closing tag
_R = REDACTED
REDACTIONS = [
    # User/system account passwords
    (r'(<password>)(.+?)(</password>)',           r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # IPsec pre-shared keys (<Key> inside <preSharedKey uuid="..."> blocks)
    (r'(<Key>)(.+?)(</Key>)',                     r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # API key blocks — self-closing <apikeys/> is left untouched
    (r'(<apikeys>)(.+?)(</apikeys>)',             r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # Certificate private keys
    (r'(<prv>)(.+?)(</prv>)',                     r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # Public certificates — contain PII (email, location) in subject/SAN fields
    (r'(<crt>)(.+?)(</crt>)',                     r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # RADIUS shared secrets, TOTP seeds, and similar auth secrets
    (r'(<secret>)(.+?)(</secret>)',               r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # Bearer/API/tunnel tokens (e.g. Cloudflare tunnel JWTs)
    (r'(<token>)(.+?)(</token>)',                 r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # SSH authorised keys — public keys but identifying
    (r'(<authorizedkeys>)(.+?)(</authorizedkeys>)', r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # Hardware MAC addresses — unique device identifiers
    (r'(<hwaddr>)(.+?)(</hwaddr>)',               r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # VPN peer identities (domain names, email-style IDs like rick.vpn, em.laptop)
    (r'(<ident>)(.+?)(</ident>)',                 r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    (r'(<remote_ident>)(.+?)(</remote_ident>)',   r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # UPnP friendly name
    (r'(<friendly_name>)(.+?)(</friendly_name>)', r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # DHCP static mapping hostnames
    (r'(<host>)(.+?)(</host>)',                   r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # Local/search domain names
    (r'(<domain>)(.+?)(</domain>)',               r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # Usernames — often email-style or IP-qualified (e.g. root@192.168.x.x in audit logs)
    (r'(<username>)(.+?)(</username>)',           r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # IPsec phase1 local/remote identifier (holds domain names or email-style IDs)
    (r'(<id>)(.+?)(</id>)',                       r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # Cloudflare tunnel / ACME hostnames
    (r'(<hostnames>)(.+?)(</hostnames>)',         r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # DNS override zone names
    (r'(<zone>)(.+?)(</zone>)',                   r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # Firewall rule audit entries (change history; may include usernames and source IPs)
    (r'(<audit>)(.+?)(</audit>)',                 r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # GeoIP alias settings — the MaxMind download URL embeds the licence key
    (r'(<geoip>)(.+?)(</geoip>)',                 r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # WireGuard public keys — not secret, but identify peers and endpoints
    (r'(<pubkey>)(.+?)(</pubkey>)',               r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # WireGuard private keys
    (r'(<privkey>)(.+?)(</privkey>)',             r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # CrowdSec console enrolment key
    (r'(<enroll_key>)(.+?)(</enroll_key>)',       r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # Zenarmor machine prefix — unique device identifier
    (r'(<Prefix>)(.+?)(</Prefix>)',               r'\g<1>' + _R + r'\g<3>', re.DOTALL),
    # Zenarmor cluster UUID — unique device identifier
    (r'(<ClusterUUID>)(.+?)(</ClusterUUID>)',     r'\g<1>' + _R + r'\g<3>', re.DOTALL),
]

# Tags that may hold IP addresses; public IPs are replaced with generic ones.
# <gateway> often holds a name string in interface blocks, but is an IP in the
# gateways section — is_public_ip() will leave non-IP values untouched.
IP_ADDRESS_TAGS = ('ipaddr', 'ipaddrv6', 'gateway')


def is_public_ip(s):
    """Return True if s is a valid, globally-routable IP address.

    Uses ip_address.is_global which follows IANA registries. Note: is_global
    semantics changed in Python 3.11 to correctly exclude TEST-NET ranges
    (192.0.2/24, 198.51.100/24, 203.0.113/24) and CGNAT (100.64/10).
    """
    try:
        ip = ipaddress.ip_address(s.strip())
        return ip.is_global
    except ValueError:
        return False  # not an IP address — leave it alone


def replace_public_ip(match):
    tag_open, ip_str, tag_close = match.group(1), match.group(2), match.group(3)
    if is_public_ip(ip_str):
        placeholder = GENERIC_IPV6 if ':' in ip_str.strip() else GENERIC_IPV4
        return f'{tag_open}{placeholder}{tag_close}'
    return match.group(0)


def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <config.xml>', file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    base, ext = os.path.splitext(input_path)
    output_path = f'{base}-redacted{ext or ".xml"}'

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except OSError as e:
        print(f'Error reading {input_path}: {e}', file=sys.stderr)
        sys.exit(1)

    # --- Sensitive field redactions ---
    for pattern, replacement, flags in REDACTIONS:
        content = re.sub(pattern, replacement, content, flags=flags)

    # --- Public IP replacement ---
    ip_replacements = 0
    for tag in IP_ADDRESS_TAGS:
        def _replace(m, _tag=tag):
            nonlocal ip_replacements
            result = replace_public_ip(m)
            if result != m.group(0):
                ip_replacements += 1
            return result

        content = re.sub(rf'(<{tag}>)([^<]+)(</{tag}>)', _replace, content)

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
    except OSError as e:
        print(f'Error writing {output_path}: {e}', file=sys.stderr)
        sys.exit(1)

    redacted_fields = content.count(REDACTED)
    print(
        f'Done: {redacted_fields} field(s) redacted, '
        f'{ip_replacements} public IP(s) replaced → {output_path}'
    )


if __name__ == '__main__':
    main()
