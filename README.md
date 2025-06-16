# iker.py

An ike-scan based security assessment tool for IPsec-based VPNs that identifies common misconfigurations and security flaws.

## Overview

**iker** v1.2 is a Python security tool that analyzes IPsec VPN implementations for security vulnerabilities and misconfigurations. It uses the `ike-scan` tool to probe IKE (Internet Key Exchange) services and identify potential security issues including weak cryptographic algorithms, insecure authentication methods, and configuration flaws.

Originally developed by Julio Gomez Ortega at Portcullis Security, this version includes modifications for enhanced algorithm support and improved Python 2/3 compatibility.

## Features

- **IKE Service Discovery**: Automatically discovers IKE services on target networks
- **Version Detection**: Identifies support for IKE v1 and v2
- **Device Fingerprinting**: 
  - Vendor identification via VID (Vendor ID) analysis
  - Implementation fingerprinting through response analysis
- **Cryptographic Analysis**:
  - Weak encryption algorithms (DES, 3DES, IDEA, Blowfish, RC5, CAST)
  - Insecure hash algorithms (MD5, SHA-1)
  - Weak Diffie-Hellman groups (MODP-768, MODP-1024, MODP-1536)
  - Vulnerable authentication methods (PSK, various signature methods)
- **Aggressive Mode Testing**: Detects and exploits aggressive mode vulnerabilities
- **Client ID Enumeration**: Dictionary-based enumeration of valid client identifiers
- **Multiple Output Formats**: Text and XML reporting

## Requirements

### Dependencies
- **Python 2.7+ or Python 3.x**
- **ike-scan**: Must be installed and accessible in PATH
- **Root privileges**: Required for network operations

### Installation

1. **Install ike-scan**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install ike-scan
   
   # CentOS/RHEL
   sudo yum install ike-scan
   
   # From source
   wget https://github.com/royhills/ike-scan/releases/latest
   ```

2. **Download iker.py**:
   ```bash
   wget https://labs.portcullis.co.uk/tools/iker/iker.py
   chmod +x iker.py
   ```

## Usage

### Basic Syntax
```bash
sudo python iker.py [OPTIONS] TARGET
```

### Target Specification
- **Single IP**: `192.168.1.1`
- **CIDR notation**: `192.168.1.0/24`
- **Input file**: `-i targets.txt` (one IP/network per line)

### Common Examples

**Basic scan of a single target:**
```bash
sudo python iker.py 192.168.1.1
```

**Scan a network range with verbose output:**
```bash
sudo python iker.py -v 10.0.0.0/24
```

**Scan from file with custom output:**
```bash
sudo python iker.py -i targets.txt -o results.txt -x results.xml
```

**Full algorithm testing (comprehensive but slow):**
```bash
sudo python iker.py --fullalgs 192.168.1.1
```

**Client ID enumeration with dictionary:**
```bash
sudo python iker.py -c client_ids.txt 192.168.1.1
```

## Command Line Options

### Target Options
- `target` - IP address or network in CIDR notation
- `-i, --input FILE` - Input file with IP addresses/networks (one per line)

### Output Options
- `-o, --output FILE` - Output file for results
- `-x, --xml FILE` - XML output file (default: iker_output.xml)
- `-v, --verbose` - Enable verbose output

### Algorithm Testing
- `--encalgs "1 5 7"` - Encryption algorithms to test (default: DES, 3DES, AES)
- `--hashalgs "1 2"` - Hash algorithms to test (default: MD5, SHA1)
- `--authmethods "1 3 64221 65001"` - Authentication methods (default: PSK, RSA Sig, Hybrid, XAUTH)
- `--kegroups "1 2 5 14"` - Key exchange groups (default: MODP-768, MODP-1024, MODP-1536, MODP-2048)
- `--fullalgs` - Test all known algorithms (comprehensive but time-consuming)

### Advanced Options
- `-d, --delay MS` - Delay between requests in milliseconds (default: 0)
- `-c, --clientids FILE` - Dictionary file for client ID enumeration
- `-n, --nofingerprint` - Skip device fingerprinting
- `--ikepath PATH` - Full path to ike-scan if not in PATH

## Security Flaws Detected

### Critical Issues
- **IKE Service Discovery**: Unauthorized access to VPN infrastructure
- **Weak Encryption**: DES, 3DES, IDEA, Blowfish, RC5, CAST algorithms
- **Insecure Hashing**: MD5, SHA-1 algorithms
- **Weak Key Exchange**: Diffie-Hellman groups < 2048 bits
- **Aggressive Mode**: Exposes group names without encryption
- **Client ID Enumeration**: Unauthorized user discovery

### Authentication Vulnerabilities
- **Pre-Shared Keys (PSK)**: Vulnerable to dictionary attacks
- **Weak Signature Methods**: DSA, RSA encryption, ElGamal variants
- **Legacy Authentication**: CRACK, Hybrid modes

## Output Format

### Text Output
```
Results for IP 192.168.1.1:
[*] The IKE service could be discovered...
[*] The following weak IKE version was supported: version 1
[*] The following weak encryption algorithm was supported: DES
[*] Aggressive Mode was accepted by the IKE service...
```

### XML Output
Structured XML format suitable for automated processing and integration with other security tools.

## Security Considerations

⚠️ **Important Security Notes:**

1. **Authorization Required**: Only test systems you own or have explicit permission to test
2. **Legal Compliance**: Ensure compliance with local laws and regulations
3. **Network Impact**: Testing may trigger security alerts and consume bandwidth
4. **Root Privileges**: Required for raw socket operations

## Performance Notes

- **Full algorithm testing** (`--fullalgs`) can be very time-intensive
- **Large networks** may require significant time for comprehensive testing
- **Delay option** (`-d`) can help avoid overwhelming target systems
- **Aggressive mode testing** generates multiple connection attempts

## Troubleshooting

### Common Issues

**"ike-scan could not be found"**
```bash
# Specify full path
sudo python iker.py --ikepath /usr/bin/ike-scan target

# Or add to PATH
export PATH=$PATH:/path/to/ike-scan
```

**"This script requires root privileges"**
```bash
# Run with sudo
sudo python iker.py target
```

**"No IKE service was found"**
- Verify target IP addresses are correct
- Check if UDP port 500 is accessible
- Confirm IKE service is running on targets

## License

GPL v3 License - http://www.gnu.org/licenses/gpl-3.0.html

## Credits

- **Original Author**: Julio Gomez Ortega (JGO@portcullis-security.com)
- **Organization**: Portcullis Security
- **Website**: https://labs.portcullis.co.uk/tools/iker/

## Version History

- **v1.2**: Added all known algorithms, Python 2/3 support, improved standards compliance
- **v1.1**: Enhanced algorithm support
- **v1.0**: Initial release

## Disclaimer

This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized use may violate laws and regulations.
