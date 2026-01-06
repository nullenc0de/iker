# iker - IKE VPN Security Assessment Tool

**Version:** 1.3-enhanced

A comprehensive IPsec VPN security assessment tool based on ike-scan. This enhanced version adds automatic PSK hash capture, MFA detection, group enumeration, and hashcat-ready output.

## Features

- **IKEv1/IKEv2 Detection** - Identifies supported IKE versions
- **Aggressive Mode Testing** - Detects vulnerable Aggressive Mode configurations
- **PSK Hash Capture** - Automatically captures Pre-Shared Key hashes for offline cracking
- **Hashcat-Ready Output** - Saves hashes in hashcat mode 5400 format
- **Group Name Enumeration** - 67 built-in common VPN group names
- **MFA Detection** - Tests for XAUTH and other multi-factor authentication methods
- **VPN Identity Extraction** - Extracts the VPN server's identity from responses
- **Quick Password Crack** - Tests 73 common VPN passwords automatically
- **Vendor Fingerprinting** - Identifies VPN vendor via VID and response analysis

## Supported VPN Vendors

| Vendor | Status | Notes |
|--------|--------|-------|
| SonicWall | Tested | Full support including vendor-specific groups |
| Cisco | Supported | Includes AnyConnect group names |
| Fortinet/FortiGate | Supported | Includes FortiGate group names |
| Juniper | Supported | Standard IKEv1 |
| Palo Alto | Supported | Standard IKEv1 |
| CheckPoint | Supported | Standard IKEv1 |
| Any IKEv1 VPN | Supported | If Aggressive Mode + PSK enabled |

## Requirements

- Python 3.6+
- ike-scan (must be installed and in PATH)
- Root/sudo privileges (required for raw socket access)
- psk-crack (optional, for quick password cracking)

### Installation

```bash
# Install ike-scan
sudo apt install ike-scan

# Clone the repository
git clone https://github.com/nullenc0de/iker.git
cd iker

# Run with sudo
sudo python3 iker.py <target>
```

## Usage

### Basic Scan
```bash
sudo python3 iker.py 192.168.1.1
```

### Quick Scan (Faster, Common Weak Algorithms)
```bash
sudo python3 iker.py 192.168.1.1 --quickscan
```

### With Hashcat Output Directory
```bash
sudo python3 iker.py 192.168.1.1 --hashcat-dir /tmp/vpn_hashes --quickscan
```

### Full Algorithm Scan (Comprehensive but Slow)
```bash
sudo python3 iker.py 192.168.1.1 --fullalgs
```

### Custom Group Wordlist
```bash
sudo python3 iker.py 192.168.1.1 -c /path/to/groups.txt --hashcat-dir /tmp/output
```

### Verbose Output
```bash
sudo python3 iker.py 192.168.1.1 --quickscan -v
```

### Scan Multiple Targets
```bash
sudo python3 iker.py -i targets.txt --hashcat-dir /tmp/output
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `target` | Target IP address or CIDR notation |
| `-i, --input` | Input file with targets (one per line) |
| `-o, --output` | Output file for results |
| `-v, --verbose` | Verbose output |
| `--quickscan` | Fast scan with common weak algorithms |
| `--fullalgs` | Test all known algorithms (slow) |
| `--hashcat-dir` | Directory for hashcat-ready hash files |
| `-c, --clientids` | Custom group name wordlist |
| `-d, --delay` | Delay between requests (ms) |
| `-x, --xml` | XML output file |
| `-j, --json` | JSON output file |
| `--ikepath` | Custom path to ike-scan binary |
| `-n, --nofingerprint` | Skip fingerprinting |

## Example Output

```
[*] IKE version 1 is supported by 192.168.1.1
[*] IKE version 2 is NOT supported by 192.168.1.1
[*] Vendor ID identified: SonicWall-7
[*] Implementation guessed: DELL SonicWall

[*] Transform found: Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK

[*] Testing authentication methods for 192.168.1.1...
    [+] PSK (Pre-Shared Key): Accepted (No MFA)
    [-] XAUTH PSK: Rejected
    [-] RSA Signatures: Rejected
    [!] WARNING: No multi-factor authentication detected!

[*] Aggressive mode supported with transform: Enc=3DES Hash=SHA1 Auth=PSK (group: GroupVPN)
    [+] Hashcat file saved: /tmp/output/192.168.1.1_aggressive.hashcat (mode 5400)

[+] VALID GROUP FOUND: GroupVPN
    [*] Capturing PSK hash...
    [+] PSK Hash: a2658c03c79303674a477d9f8fdb0561a4edce96
    [+] VPN Identity: YOURFW
    [+] Hashcat file: /tmp/output/psk_192.168.1.1_GroupVPN.hashcat (mode 5400)

[*] Attempting quick password crack...
    Testing 73 common VPN passwords...
    [-] No match found with common passwords
```

## Cracking Captured Hashes

### Using Hashcat
```bash
# Mode 5400 = IKE-PSK SHA1
hashcat -m 5400 /tmp/output/*.hashcat /path/to/wordlist.txt

# With rules
hashcat -m 5400 /tmp/output/*.hashcat /path/to/wordlist.txt -r best64.rule
```

### Using psk-crack
```bash
psk-crack -d /path/to/wordlist.txt /tmp/output/psk_192.168.1.1_GroupVPN
```

## Built-in Group Names (67 entries)

The tool includes common VPN group names for automatic enumeration:

**Generic:**
- vpn, VPN, default, Default, ipsec, IPSec, remote, Remote
- client, Client, mobile, Mobile, users, Users, admin, Admin
- test, Test, guest, Guest, partner, vendor, contractor

**SonicWall Specific:**
- GroupVPN, WAN GroupVPN, NetExtender, GlobalVPN, SSLVPN, SSL-VPN

**Cisco Specific:**
- cisco, Cisco, anyconnect, AnyConnect

**Fortinet Specific:**
- fortigate, FortiGate, fortinet

## Security Findings Detected

| Finding | Severity | Description |
|---------|----------|-------------|
| IKEv1 Only | Medium | Legacy protocol with known weaknesses |
| Aggressive Mode | High | Exposes PSK hash to unauthenticated attackers |
| No MFA | High | Single-factor authentication only |
| Weak Encryption (DES/3DES) | Medium | Deprecated encryption algorithms |
| Weak Hash (MD5/SHA-1) | Medium | Cryptographically broken hash algorithms |
| Weak DH Group (<2048-bit) | Medium | Vulnerable to offline attacks |
| PSK Authentication | Medium | Shared secret, no per-user credentials |
| Group Name Disclosure | Low | Information leakage |

## Limitations

The tool will NOT work when:
- **IKEv2 Only** - IKEv2 doesn't expose PSK hashes (secure by design)
- **Aggressive Mode Disabled** - Cannot capture hash without Aggressive Mode
- **Certificate Auth Only** - No PSK to capture
- **Unknown Group Names** - Use `-c` with custom wordlist

## Credits

- **Original Author:** Julio Gomez Ortega (Portcullis Security)
- **Original Tool:** https://labs.portcullis.co.uk/tools/iker/
- **Enhanced Version:** nullenc0de
- **Additional Enhancements:** MFA detection, VPN ID extraction, hashcat output, quick crack

## License

GPL v3 - http://www.gnu.org/licenses/gpl-3.0.html

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before testing any systems you do not own. Unauthorized access to computer systems is illegal.
