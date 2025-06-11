#!/usr/bin/env python3
'''
iker.py script courtesy of Portcullis Security

https://labs.portcullis.co.uk/tools/iker/

Updated version with improved IKEv2 detection and modern security checks
'''

import sys
import os
import subprocess
import argparse
import re
import json
import logging
import threading
import queue
import random
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional

VERSION = "2.1"

# ike-scan full path (default assumes in PATH)
FULLIKESCANPATH = "ike-scan"

# Verbose flag
VERBOSE = False

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Algorithm lists - Updated for 2025
ENCLIST = ['5', '7/128', '7/192', '7/256', '12', '20']  # 3DES, AES variants, ChaCha20
HASHLIST = ['2', '5', '6', '7']  # SHA1, SHA256, SHA512, SHA3
AUTHLIST = ['1', '3', '9', '10', '11', '64221', '65001']  # PSK, RSA Sig, ECDSA variants, Hybrid, XAUTH
GROUPLIST = ['14', '15', '16', '19', '20', '21']  # Modern DH groups (2048+ bit, ECP)

# Full algorithm lists for comprehensive testing
FULLENCLIST = ['1', '2', '3', '4', '5', '6', '7/128', '7/192', '7/256', '8', '12', '13', '18', '19', '20', '24']
FULLENCLISTv2 = ['5', '7/128', '7/192', '7/256', '12', '13', '14', '18', '19', '20', '24', '28']
FULLHASHLIST = ['1', '2', '3', '4', '5', '6', '7', '8']
FULLHASHLISTv2 = ['2', '5', '6', '7', '8', '9', '10']
FULLAUTHLIST = ['1', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '64221', '65001']
FULLGROUPLIST = ['1', '2', '5', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26']

# Output files
XMLOUTPUT = "iker_output.xml"
JSONOUTPUT = "iker_output.json"

# Client IDs dictionary
CLIENTIDS = ""

# Delay settings
DELAY = 0
ADAPTIVE_DELAY = True

# Flaws (updated for 2025 standards)
FLAWS = {
    "DISC": "The IKE service is discoverable, which should be restricted to authorized parties",
    "IKEV1": "Weak IKE version 1 supported (deprecated in favor of IKEv2)",
    "FING_VID": "Vendor ID fingerprinting possible via VID payload",
    "FING_BACKOFF": "Service fingerprinting possible via response patterns",
    "ENC_DES": "Critical weakness: DES encryption (broken, 56-bit key)",
    "ENC_3DES": "Weak encryption: 3DES (vulnerable to Sweet32 attacks)",
    "ENC_IDEA": "Weak encryption: IDEA (outdated algorithm)",
    "ENC_BLOW": "Weak encryption: Blowfish (variable security, potential weaknesses)",
    "ENC_RC5": "Weak encryption: RC5 (outdated algorithm)",
    "ENC_CAST": "Weak encryption: CAST (outdated algorithm)",
    "HASH_MD5": "Critical weakness: MD5 hash (cryptographically broken)",
    "HASH_SHA1": "Weak hash: SHA-1 (cryptographically broken, collision attacks)",
    "DHG_1": "Critical weakness: MODP-768 DH group (insufficient 768-bit key)",
    "DHG_2": "Weak DH group: MODP-1024 (insufficient 1024-bit key)",
    "DHG_5": "Weak DH group: MODP-1536 (insufficient 1536-bit key)",
    "AUTH_PSK": "Weak authentication: PSK (vulnerable to brute-forcing and dictionary attacks)",
    "AUTH_RSA_SIG": "Moderate authentication: RSA signatures (security depends on key length)",
    "AUTH_HYBRID": "Weak authentication: Hybrid mode (potential vulnerabilities)",
    "AGGR": "Critical vulnerability: Aggressive Mode enabled (exposes authentication hash)",
    "AGGR_GRP_NO_ENC": "Information disclosure: Aggressive Mode leaks group name unencrypted",
    "CID_ENUM": "Information disclosure: Client ID enumeration possible",
    "NAT_T_MISCONFIG": "Configuration issue: NAT Traversal misconfiguration detected",
    "FRAG_VULN": "Potential DoS: IKE fragmentation vulnerability detected",
    "WEAK_LIFETIME": "Configuration issue: Excessively long SA lifetime configured",
    "DPD_DISABLED": "Configuration issue: Dead Peer Detection disabled",
    "MOBIKE_VULN": "IKEv2 MOBIKE implementation vulnerability"
}

def welcome():
    logger.info(f"iker v{VERSION} - IPsec VPN Security Scanner")
    logger.info("By Julio Gomez (jgo@portcullis-security.com), updated by xAI")
    logger.info("Enhanced IKEv2 detection and modern cryptographic analysis")

def check_privileges() -> bool:
    """Check if running with root privileges"""
    return os.geteuid() == 0

def check_ikescan() -> bool:
    """Verify ike-scan is available and working"""
    try:
        result = subprocess.run(
            [FULLIKESCANPATH, "--version"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10
        )
        if "ike-scan" in result.stderr.lower() or "ike-scan" in result.stdout.lower():
            logger.info(f"ike-scan found: {FULLIKESCANPATH}")
            return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logger.error("ike-scan not found or incompatible. Specify path with --ikepath.")
        return False
    return False

def get_arguments() -> Tuple[argparse.Namespace, List[str]]:
    """Parse command line arguments"""
    global VERBOSE, FULLIKESCANPATH, ENCLIST, HASHLIST, AUTHLIST, GROUPLIST
    global XMLOUTPUT, JSONOUTPUT, CLIENTIDS, DELAY, ADAPTIVE_DELAY

    parser = argparse.ArgumentParser(description="IPsec VPN Security Scanner")
    parser.add_argument("target", type=str, nargs='?', help="IP address or network (CIDR)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-d", "--delay", type=int, default=0, help="Delay between requests (ms)")
    parser.add_argument("--adaptive-delay", action="store_true", help="Enable adaptive rate limiting")
    parser.add_argument("-i", "--input", type=str, help="File with IP addresses/networks")
    parser.add_argument("-o", "--output", type=str, help="Output file for results")
    parser.add_argument("-x", "--xml", type=str, default=XMLOUTPUT, help="XML output file")
    parser.add_argument("-j", "--json", type=str, default=JSONOUTPUT, help="JSON output file")
    parser.add_argument("--encalgs", type=str, default="5 7/128 7/256 12 20", help="Encryption algorithms")
    parser.add_argument("--hashalgs", type=str, default="2 5 6 7", help="Hash algorithms")
    parser.add_argument("--authmethods", type=str, default="1 3 9 10 64221 65001", help="Auth methods")
    parser.add_argument("--kegroups", type=str, default="14 15 16 19 20 21", help="DH groups")
    parser.add_argument("--fullalgs", action="store_true", help="Test all known algorithms")
    parser.add_argument("--ikepath", type=str, default=FULLIKESCANPATH, help="ike-scan path")
    parser.add_argument("-c", "--clientids", type=str, help="Client ID dictionary file")
    parser.add_argument("-n", "--nofingerprint", action="store_true", help="Skip fingerprinting")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of scanning threads")
    parser.add_argument("--natt", action="store_true", help="Test NAT-T configurations")
    parser.add_argument("--frag", action="store_true", help="Test IKE fragmentation")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout for ike-scan operations")
    parser.add_argument("--retries", type=int, default=2, help="Number of retries for failed operations")

    args = parser.parse_args()
    targets = []

    # Handle target input
    if args.target:
        if re.match(r'\d+\.\d+\.\d+\.\d+(/\d+)?$', args.target):
            targets.append(args.target)
        else:
            logger.error("Target must be a valid IP address or CIDR notation")
            parser.print_help()
            sys.exit(1)

    # Handle input file
    if args.input:
        try:
            with open(args.input, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if re.match(r'\d+\.\d+\.\d+\.\d+(/\d+)?$', line):
                            targets.append(line)
                        else:
                            logger.warning(f"Skipping invalid target: {line}")
        except IOError as e:
            logger.error(f"Cannot read input file {args.input}: {e}")
            sys.exit(1)

    if not targets:
        logger.error("Specify a target or input file")
        parser.print_help()
        sys.exit(1)

    # Set global variables
    VERBOSE = args.verbose
    FULLIKESCANPATH = args.ikepath
    XMLOUTPUT = args.xml
    JSONOUTPUT = args.json
    CLIENTIDS = args.clientids
    DELAY = args.delay
    ADAPTIVE_DELAY = args.adaptive_delay

    if args.fullalgs:
        ENCLIST = FULLENCLIST
        HASHLIST = FULLHASHLIST
        AUTHLIST = FULLAUTHLIST
        GROUPLIST = FULLGROUPLIST
    else:
        ENCLIST = args.encalgs.split()
        HASHLIST = args.hashalgs.split()
        AUTHLIST = args.authmethods.split()
        GROUPLIST = args.kegroups.split()

    return args, targets

def run_command(command: str, timeout: int = 30) -> Tuple[str, str, int]:
    """Execute a command with timeout and error handling"""
    try:
        if VERBOSE:
            logger.debug(f"Executing: {command}")
        
        process = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return process.stdout, process.stderr, process.returncode
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out: {command}")
        return "", "Timeout", 1
    except Exception as e:
        logger.error(f"Command failed: {command}, error: {e}")
        return "", str(e), 1

def adaptive_sleep(base_delay: int):
    """Implement adaptive delay to avoid overwhelming targets"""
    if ADAPTIVE_DELAY:
        jitter = random.uniform(0.5, 1.5)
        time.sleep((base_delay * jitter) / 1000.0)
    elif base_delay:
        time.sleep(base_delay / 1000.0)

def update_progress_bar(current: int, total: int, transform: str):
    """Display progress bar for long operations"""
    width = 30
    percent = (current / total) * 100
    filled = int(width * current // total)
    bar = '█' * filled + '░' * (width - filled)
    sys.stdout.write(f"\r[{bar}] {percent:.1f}% - Transform: {transform}")
    sys.stdout.flush()

def discovery(args: argparse.Namespace, target: str, vpns: Dict, q: queue.Queue):
    """Discover IKEv1 services"""
    logger.info(f"Discovering IKEv1 services for {target}")
    command = f"{FULLIKESCANPATH} -M {target}"
    
    for retry in range(args.retries + 1):
        stdout, stderr, rc = run_command(command, args.timeout)
        
        if rc == 0 or stdout.strip():
            break
        
        if retry < args.retries:
            logger.warning(f"Retry {retry + 1}/{args.retries} for IKEv1 discovery on {target}")
            time.sleep(1)
    
    current_ip = None
    current_info = []
    
    for line in stdout.splitlines():
        line = line.strip()
        if not line or "Starting ike-scan" in line or "Ending ike-scan" in line:
            continue
            
        # Check if this line contains an IP address (start of new host)
        ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            # Save previous host data if exists
            if current_ip and current_info:
                vpns[current_ip] = {
                    "handshake": "\n".join(current_info), 
                    "v1": True,
                    "v2": False,
                    "transforms": [],
                    "aggressive": [],
                    "vid": []
                }
                q.put((current_ip, "v1", True))
                logger.info(f"IKEv1 supported by {current_ip}")
            
            # Start new host
            current_ip = ip_match.group(1)
            current_info = [line]
        else:
            # Continuation of current host data
            if current_ip:
                current_info.append(line)
    
    # Don't forget the last host
    if current_ip and current_info:
        vpns[current_ip] = {
            "handshake": "\n".join(current_info), 
            "v1": True,
            "v2": False,
            "transforms": [],
            "aggressive": [],
            "vid": []
        }
        q.put((current_ip, "v1", True))
        logger.info(f"IKEv1 supported by {current_ip}")

def check_ikev2(args: argparse.Namespace, target: str, vpns: Dict, q: queue.Queue):
    """Check for IKEv2 support - Fixed logic"""
    logger.info(f"Checking IKEv2 support for {target}")
    command = f"{FULLIKESCANPATH} -2 -M {target}"
    
    for retry in range(args.retries + 1):
        stdout, stderr, rc = run_command(command, args.timeout)
        
        if rc == 0 or stdout.strip():
            break
        
        if retry < args.retries:
            logger.warning(f"Retry {retry + 1}/{args.retries} for IKEv2 discovery on {target}")
            time.sleep(1)
    
    current_ip = None
    current_info = []
    
    for line in stdout.splitlines():
        line = line.strip()
        if not line or "Starting ike-scan" in line or "Ending ike-scan" in line:
            continue
            
        # Check if this line contains an IP address
        ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            # Save previous host data if exists
            if current_ip and current_info:
                # Initialize the IP entry if it doesn't exist
                if current_ip not in vpns:
                    vpns[current_ip] = {
                        "v1": False,
                        "v2": False,
                        "transforms": [],
                        "aggressive": [],
                        "vid": []
                    }
                
                vpns[current_ip]["v2"] = True
                vpns[current_ip]["handshake_v2"] = "\n".join(current_info)
                q.put((current_ip, "v2", True))
                logger.info(f"IKEv2 supported by {current_ip}")
            
            # Start new host
            current_ip = ip_match.group(1)
            current_info = [line]
        else:
            # Continuation of current host data
            if current_ip:
                current_info.append(line)
    
    # Don't forget the last host
    if current_ip and current_info:
        # Initialize the IP entry if it doesn't exist
        if current_ip not in vpns:
            vpns[current_ip] = {
                "v1": False,
                "v2": False,
                "transforms": [],
                "aggressive": [],
                "vid": []
            }
        
        vpns[current_ip]["v2"] = True
        vpns[current_ip]["handshake_v2"] = "\n".join(current_info)
        q.put((current_ip, "v2", True))
        logger.info(f"IKEv2 supported by {current_ip}")

def fingerprint_vid(args: argparse.Namespace, vpns: Dict, ip: str, handshake: str):
    """Extract and analyze Vendor ID payloads"""
    if "vid" not in vpns[ip]:
        vpns[ip]["vid"] = []

    transform = ""
    vid_entries = []
    
    for line in handshake.splitlines():
        if "SA=" in line:
            transform = line.strip()[4:-1] if len(line) > 4 else line.strip()
        if "VID=" in line and "(" in line and ")" in line:
            # Extract VID description
            start = line.find('(')
            end = line.find(')', start)
            if start != -1 and end != -1 and "draft-ietf" not in line:
                vid = line[start+1:end]
                vid_entries.append(vid)

    # Store unique VIDs
    for vid in vid_entries:
        if vid and vid not in [v[0] for v in vpns[ip]["vid"]]:
            vpns[ip]["vid"].append((vid, handshake))
            logger.info(f"Vendor ID for {ip}: {vid} (Transform: {transform})")

def fingerprint_backoff(args: argparse.Namespace, vpns: Dict, ip: str, transform: str = ""):
    """Perform backoff-based implementation fingerprinting"""
    if args.nofingerprint:
        return

    logger.info(f"Fingerprinting {ip} via backoff analysis")
    
    # Build command with optional transform
    cmd_parts = [FULLIKESCANPATH, "--showbackoff"]
    if transform:
        cmd_parts.append(f"--trans={transform}")
    cmd_parts.append(ip)
    
    cmd = " ".join(cmd_parts)
    stdout, stderr, rc = run_command(cmd, args.timeout)

    for line in stdout.splitlines():
        if "Implementation guess:" in line:
            vendor = line.split("Implementation guess:")[1].strip()
            if vendor.lower() != "unknown":
                vpns[ip]["showbackoff"] = vendor
                logger.info(f"Implementation detected for {ip}: {vendor}")
                return
    
    # Check stderr for additional info
    for line in stderr.splitlines():
        if "Implementation guess:" in line:
            vendor = line.split("Implementation guess:")[1].strip()
            if vendor.lower() != "unknown":
                vpns[ip]["showbackoff"] = vendor
                logger.info(f"Implementation detected for {ip}: {vendor}")
                return
    
    vpns[ip]["showbackoff"] = "Unknown"
    if VERBOSE:
        logger.debug(f"Could not fingerprint {ip} via backoff")

def check_encryption_algs(args: argparse.Namespace, vpns: Dict, ip: str, q: queue.Queue):
    """Test supported encryption algorithms and transforms"""
    logger.info(f"Testing encryption algorithms for {ip}")
    
    total = len(ENCLIST) * len(HASHLIST) * len(AUTHLIST) * len(GROUPLIST)
    current = 0
    
    if "transforms" not in vpns[ip]:
        vpns[ip]["transforms"] = []

    # Randomize order to avoid patterns
    enc_shuffled = random.sample(ENCLIST, len(ENCLIST))
    hash_shuffled = random.sample(HASHLIST, len(HASHLIST))
    auth_shuffled = random.sample(AUTHLIST, len(AUTHLIST))
    group_shuffled = random.sample(GROUPLIST, len(GROUPLIST))

    for enc in enc_shuffled:
        for hsh in hash_shuffled:
            for auth in auth_shuffled:
                for group in group_shuffled:
                    current += 1
                    transform = f"{enc},{hsh},{auth},{group}"
                    
                    if not VERBOSE:
                        update_progress_bar(current, total, transform)
                    
                    cmd = f"{FULLIKESCANPATH} -M --trans={transform} {ip}"
                    stdout, stderr, rc = run_command(cmd, args.timeout)

                    # Parse response
                    info_lines = []
                    found_sa = False
                    
                    for line in stdout.splitlines():
                        if "Starting ike-scan" in line or "Ending ike-scan" in line or not line.strip():
                            continue
                        info_lines.append(line)
                        if "SA=" in line:
                            found_sa = True
                            sa_desc = line[4:-1] if len(line) > 4 else line
                            
                            if VERBOSE:
                                logger.info(f"Transform accepted by {ip}: {sa_desc}")
                            else:
                                logger.info(f"Transform found for {ip}: {sa_desc}")

                    if found_sa and info_lines:
                        handshake_data = "\n".join(info_lines)
                        vpns[ip]["transforms"].append((transform, sa_desc, handshake_data))
                        q.put((ip, "transform", sa_desc))
                        
                        # Extract VID information
                        fingerprint_vid(args, vpns, ip, handshake_data)
                        
                        # Perform backoff fingerprinting if not done yet
                        if not vpns[ip].get("showbackoff"):
                            fingerprint_backoff(args, vpns, ip, transform)

                    adaptive_sleep(DELAY)

    if not VERBOSE:
        print()  # New line after progress bar

def check_aggressive(args: argparse.Namespace, vpns: Dict, ip: str, q: queue.Queue):
    """Test for Aggressive Mode support"""
    logger.info(f"Testing Aggressive Mode for {ip}")
    
    total = len(ENCLIST) * len(HASHLIST) * len(AUTHLIST) * len(GROUPLIST)
    current = 0
    
    if "aggressive" not in vpns[ip]:
        vpns[ip]["aggressive"] = []

    # Test with randomized algorithms
    enc_shuffled = random.sample(ENCLIST, len(ENCLIST))
    hash_shuffled = random.sample(HASHLIST, len(HASHLIST))
    auth_shuffled = random.sample(AUTHLIST, len(AUTHLIST))  
    group_shuffled = random.sample(GROUPLIST, len(GROUPLIST))

    for enc in enc_shuffled:
        for hsh in hash_shuffled:
            for auth in auth_shuffled:
                for group in group_shuffled:
                    current += 1
                    transform = f"{enc},{hsh},{auth},{group}"
                    
                    if not VERBOSE:
                        update_progress_bar(current, total, f"Aggressive: {transform}")
                    
                    # Create unique filename for handshake capture
                    handshake_file = f"/tmp/{ip}_{current}_handshake.txt"
                    cmd = f"{FULLIKESCANPATH} -M --aggressive -P{handshake_file} --trans={transform} {ip}"
                    stdout, stderr, rc = run_command(cmd, args.timeout)

                    # Parse response
                    info_lines = []
                    found_sa = False
                    
                    for line in stdout.splitlines():
                        if "Starting ike-scan" in line or "Ending ike-scan" in line or not line.strip():
                            continue
                        info_lines.append(line)
                        if "SA=" in line:
                            found_sa = True
                            sa_desc = line[4:-1] if len(line) > 4 else line
                            logger.warning(f"AGGRESSIVE MODE supported by {ip}: {sa_desc}")

                    if found_sa and info_lines:
                        handshake_data = "\n".join(info_lines)
                        vpns[ip]["aggressive"].append((transform, sa_desc, handshake_data))
                        q.put((ip, "aggressive", sa_desc))
                        
                        # Extract VID information
                        fingerprint_vid(args, vpns, ip, handshake_data)
                        
                        # Perform backoff fingerprinting if not done yet
                        if not vpns[ip].get("showbackoff"):
                            fingerprint_backoff(args, vpns, ip, transform)
                    
                    # Clean up handshake file
                    try:
                        if os.path.exists(handshake_file):
                            os.remove(handshake_file)
                    except:
                        pass

                    adaptive_sleep(DELAY)

    if not VERBOSE:
        print()  # New line after progress bar

def enumerate_client_ids(args: argparse.Namespace, vpns: Dict, ip: str, q: queue.Queue):
    """Enumerate valid client IDs if aggressive mode is supported"""
    if not args.clientids or not vpns[ip].get("aggressive"):
        return

    logger.info(f"Enumerating client IDs for {ip}")
    
    # Use first working aggressive mode transform
    transform = vpns[ip]["aggressive"][0][0]
    
    # Generate baseline with known invalid IDs
    invalid_ids = [
        "badgroupiker123", "invalidclient456", "nonexistentuser789", 
        "fakeid000", "bogusgroup999"
    ]
    invalid_responses = []

    for cid in invalid_ids:
        cmd = f"{FULLIKESCANPATH} --aggressive --trans={transform} --id={cid} {ip}"
        stdout, stderr, rc = run_command(cmd, args.timeout)
        
        # Normalize response by removing variable data like HDR values
        normalized = re.sub(r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', stdout.strip())
        invalid_responses.append(normalized)
        adaptive_sleep(DELAY)

    # Determine most common invalid response pattern
    if invalid_responses:
        invalid_pattern = max(set(invalid_responses), key=invalid_responses.count)
    else:
        logger.warning(f"Could not determine invalid client ID pattern for {ip}")
        return

    # Test client IDs from file
    try:
        with open(args.clientids, "r") as f:
            client_ids = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        # Randomize to avoid detection patterns
        random.shuffle(client_ids)
        
        if "clientids" not in vpns[ip]:
            vpns[ip]["clientids"] = []
        
        tested = 0
        found = 0
        
        for cid in client_ids:
            cmd = f"{FULLIKESCANPATH} --aggressive --trans={transform} --id={cid} {ip}"
            stdout, stderr, rc = run_command(cmd, args.timeout)
            
            # Normalize response
            normalized = re.sub(r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', stdout.strip())
            
            if normalized and normalized != invalid_pattern:
                vpns[ip]["clientids"].append(cid)
                q.put((ip, "clientid", cid))
                found += 1
                logger.info(f"Valid client ID found for {ip}: {cid}")
            
            tested += 1
            if tested % 50 == 0:
                logger.info(f"Tested {tested} client IDs for {ip}, found {found} valid")
            
            adaptive_sleep(DELAY)
            
    except IOError as e:
        logger.error(f"Cannot read client ID file {args.clientids}: {e}")

def check_natt(args: argparse.Namespace, vpns: Dict, ip: str, q: queue.Queue):
    """Test NAT Traversal support"""
    if not args.natt:
        return

    logger.info(f"Testing NAT-T support for {ip}")
    
    # Test standard NAT-T
    cmd = f"{FULLIKESCANPATH} --nat-t {ip}"
    stdout, stderr, rc = run_command(cmd, args.timeout)
    
    natt_detected = False
    if "NAT-T" in stdout or "nat-t" in stdout.lower():
        natt_detected = True
        vpns[ip]["natt"] = True
        q.put((ip, "natt", True))
        logger.warning(f"NAT-T enabled on {ip}")
    
    # Test NAT-T on port 4500
    cmd = f"{FULLIKESCANPATH} --sport=4500 --dport=4500 {ip}"
    stdout2, stderr2, rc2 = run_command(cmd, args.timeout)
    
    if not natt_detected and ("SA=" in stdout2 or "IKE" in stdout2):
        vpns[ip]["natt"] = True
        q.put((ip, "natt", True))
        logger.warning(f"NAT-T detected on port 4500 for {ip}")
    
    if not vpns[ip].get("natt"):
        vpns[ip]["natt"] = False

def check_fragmentation(args: argparse.Namespace, vpns: Dict, ip: str, q: queue.Queue):
    """Test IKE fragmentation support"""
    if not args.frag:
        return

    logger.info(f"Testing IKE fragmentation for {ip}")
    
    # Test with large payload that would require fragmentation
    cmd = f"{FULLIKESCANPATH} --trans=7/256,5,1,14 --frag {ip}"
    stdout, stderr, rc = run_command(cmd, args.timeout)
    
    if "Fragmentation" in stdout or "frag" in stdout.lower():
        vpns[ip]["frag"] = True
        q.put((ip, "frag", True))
        logger.warning(f"IKE fragmentation supported on {ip} - potential DoS vector")
    else:
        vpns[ip]["frag"] = False

def check_ikev2_specific(args: argparse.Namespace, vpns: Dict, ip: str, q: queue.Queue):
    """Test IKEv2-specific vulnerabilities and features"""
    if not vpns[ip].get("v2"):
        return
    
    logger.info(f"Testing IKEv2-specific features for {ip}")
    
    # Test MOBIKE support
    cmd = f"{FULLIKESCANPATH} -2 --mobike {ip}"
    stdout, stderr, rc = run_command(cmd, args.timeout)
    
    if "MOBIKE" in stdout:
        vpns[ip]["mobike"] = True
        # Check for known MOBIKE vulnerabilities
        if "vulnerable" in stdout.lower() or "weak" in stdout.lower():
            q.put((ip, "mobike_vuln", True))
            logger.warning(f"MOBIKE vulnerability detected on {ip}")
    
    # Test EAP support
    cmd = f"{FULLIKESCANPATH} -2 --eap {ip}"
    stdout, stderr, rc = run_command(cmd, args.timeout)
    
    if "EAP" in stdout:
        vpns[ip]["eap"] = True
        logger.info(f"EAP support detected on {ip}")
    
    # Test Certificate-based auth
    cmd = f"{FULLIKESCANPATH} -2 --cert {ip}"
    stdout, stderr, rc = run_command(cmd, args.timeout)
    
    if "Certificate" in stdout or "CERT" in stdout:
        vpns[ip]["cert_auth"] = True
        logger.info(f"Certificate authentication supported on {ip}")

def scan_target(args: argparse.Namespace, target: str, vpns: Dict, result_queue: queue.Queue):
    """Main scanning function for a target"""
    try:
        logger.info(f"Starting comprehensive scan of {target}")
        
        # Phase 1: Discovery
        discovery(args, target, vpns, result_queue)
        check_ikev2(args, target, vpns, result_queue)
        
        # Phase 2: Detailed analysis for discovered services
        for ip in list(vpns.keys()):
            logger.info(f"Analyzing discovered service at {ip}")
            
            # Basic fingerprinting
            if vpns[ip].get("handshake"):
                fingerprint_vid(args, vpns, ip, vpns[ip]["handshake"])
            fingerprint_backoff(args, vpns, ip)
            
            # Algorithm testing
            check_encryption_algs(args, vpns, ip, result_queue)
            
            # Vulnerability testing
            check_aggressive(args, vpns, ip, result_queue)
            enumerate_client_ids(args, vpns, ip, result_queue)
            
            # Protocol-specific tests
            check_natt(args, vpns, ip, result_queue)
            check_fragmentation(args, vpns, ip, result_queue)
            check_ikev2_specific(args, vpns, ip, result_queue)
            
            logger.info(f"Completed analysis of {ip}")
            
    except Exception as e:
        logger.error(f"Error scanning {target}: {e}")
        if VERBOSE:
            import traceback
            logger.error(traceback.format_exc())

def analyze_security_flaws(vpns: Dict) -> Dict:
    """Analyze discovered configurations for security flaws"""
    results = {"services": {}, "summary": {"total_hosts": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}}
    
    for ip, data in vpns.items():
        results["services"][ip] = {"flaws": [], "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
        results["summary"]["total_hosts"] += 1
        
        # Service discovery (always flagged)
        flaw = {"description": FLAWS["DISC"], "severity": "medium", "data": data.get("handshake", "")}
        results["services"][ip]["flaws"].append(flaw)
        results["services"][ip]["severity_counts"]["medium"] += 1
        
        # IKEv1 support
        if data.get("v1"):
            flaw = {"description": FLAWS["IKEV1"], "severity": "high", "data": ""}
            results["services"][ip]["flaws"].append(flaw)
            results["services"][ip]["severity_counts"]["high"] += 1
        
        # Vendor ID fingerprinting
        for vid, handshake in data.get("vid", []):
            flaw = {"description": f"{FLAWS['FING_VID']}: {vid}", "severity": "low", "data": handshake}
            results["services"][ip]["flaws"].append(flaw)
            results["services"][ip]["severity_counts"]["low"] += 1
        
        # Implementation fingerprinting
        if data.get("showbackoff") and data["showbackoff"] != "Unknown":
            flaw = {"description": f"{FLAWS['FING_BACKOFF']}: {data['showbackoff']}", "severity": "low", "data": ""}
            results["services"][ip]["flaws"].append(flaw)
            results["services"][ip]["severity_counts"]["low"] += 1
        
        # Analyze transforms for weak algorithms
        for transform, desc, info in data.get("transforms", []):
            severity = "medium"
            
            # Critical encryption flaws
            if "Enc=DES(" in desc:
                flaw = {"description": FLAWS["ENC_DES"], "severity": "critical", "data": info}
                results["services"][ip]["flaws"].append(flaw)
                results["services"][ip]["severity_counts"]["critical"] += 1
                severity = "critical"
            
            if "Enc=3DES(" in desc:
                flaw = {"description": FLAWS["ENC_3DES"], "severity": "high", "data": info}
                results["services"][ip]["flaws"].append(flaw)
                results["services"][ip]["severity_counts"]["high"] += 1
            
            # Critical hash flaws
            if "Hash=MD5(" in desc:
                flaw = {"description": FLAWS["HASH_MD5"], "severity": "critical", "data": info}
                results["services"][ip]["flaws"].append(flaw)
                results["services"][ip]["severity_counts"]["critical"] += 1
            
            if "Hash=SHA(" in desc or "Hash=SHA1(" in desc:
                flaw = {"description": FLAWS["HASH_SHA1"], "severity": "high", "data": info}
                results["services"][ip]["flaws"].append(flaw)
                results["services"][ip]["severity_counts"]["high"] += 1
            
            # Critical DH group flaws
            if "Group=1(" in desc:
                flaw = {"description": FLAWS["DHG_1"], "severity": "critical", "data": info}
                results["services"][ip]["flaws"].append(flaw)
                results["services"][ip]["severity_counts"]["critical"] += 1
            
            if "Group=2(" in desc:
                flaw = {"description": FLAWS["DHG_2"], "severity": "high", "data": info}
                results["services"][ip]["flaws"].append(flaw)
                results["services"][ip]["severity_counts"]["high"] += 1
            
            if "Group=5(" in desc:
                flaw = {"description": FLAWS["DHG_5"], "severity": "high", "data": info}
                results["services"][ip]["flaws"].append(flaw)
                results["services"][ip]["severity_counts"]["high"] += 1
            
            # Authentication method analysis
            if "Auth=PSK(" in desc:
                flaw = {"description": FLAWS["AUTH_PSK"], "severity": "medium", "data": info}
                results["services"][ip]["flaws"].append(flaw)
                results["services"][ip]["severity_counts"]["medium"] += 1
            
            if "Auth=RSA_Sig(" in desc:
                flaw = {"description": FLAWS["AUTH_RSA_SIG"], "severity": "low", "data": info}
                results["services"][ip]["flaws"].append(flaw)
                results["services"][ip]["severity_counts"]["low"] += 1
        
        # Aggressive mode (critical vulnerability)
        for transform, desc, info in data.get("aggressive", []):
            flaw = {"description": f"{FLAWS['AGGR']}: {desc}", "severity": "critical", "data": info}
            results["services"][ip]["flaws"].append(flaw)
            results["services"][ip]["severity_counts"]["critical"] += 1
            
            flaw = {"description": FLAWS["AGGR_GRP_NO_ENC"], "severity": "high", "data": ""}
            results["services"][ip]["flaws"].append(flaw)
            results["services"][ip]["severity_counts"]["high"] += 1
        
        # Client ID enumeration
        if data.get("clientids"):
            client_list = ", ".join(data["clientids"][:10])  # Limit output
            if len(data["clientids"]) > 10:
                client_list += f" (and {len(data['clientids']) - 10} more)"
            flaw = {"description": f"{FLAWS['CID_ENUM']}: {client_list}", "severity": "medium", "data": ""}
            results["services"][ip]["flaws"].append(flaw)
            results["services"][ip]["severity_counts"]["medium"] += 1
        
        # NAT-T misconfiguration
        if data.get("natt"):
            flaw = {"description": FLAWS["NAT_T_MISCONFIG"], "severity": "low", "data": ""}
            results["services"][ip]["flaws"].append(flaw)
            results["services"][ip]["severity_counts"]["low"] += 1
        
        # IKE fragmentation
        if data.get("frag"):
            flaw = {"description": FLAWS["FRAG_VULN"], "severity": "medium", "data": ""}
            results["services"][ip]["flaws"].append(flaw)
            results["services"][ip]["severity_counts"]["medium"] += 1
        
        # MOBIKE vulnerabilities
        if data.get("mobike_vuln"):
            flaw = {"description": FLAWS["MOBIKE_VULN"], "severity": "high", "data": ""}
            results["services"][ip]["flaws"].append(flaw)
            results["services"][ip]["severity_counts"]["high"] += 1
        
        # Update summary counts
        for severity, count in results["services"][ip]["severity_counts"].items():
            results["summary"][severity] += count
    
    return results

def generate_reports(args: argparse.Namespace, vpns: Dict, start_time: str, end_time: str):
    """Generate XML and JSON reports"""
    results = analyze_security_flaws(vpns)
    
    # Add metadata
    results["scan_info"] = {
        "version": VERSION,
        "start_time": start_time,
        "end_time": end_time,
        "total_duration": str(datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S") - 
                             datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")),
        "algorithms_tested": {
            "encryption": ENCLIST,
            "hash": HASHLIST,
            "authentication": AUTHLIST,
            "dh_groups": GROUPLIST
        }
    }
    
    # Generate XML report
    with open(args.xml, "w", encoding="utf-8") as fxml:
        fxml.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        fxml.write(f'<iker_results version="{VERSION}" start_time="{start_time}" end_time="{end_time}">\n')
        
        # Summary section
        fxml.write('  <summary>\n')
        fxml.write(f'    <total_hosts>{results["summary"]["total_hosts"]}</total_hosts>\n')
        fxml.write(f'    <critical_issues>{results["summary"]["critical"]}</critical_issues>\n')
        fxml.write(f'    <high_issues>{results["summary"]["high"]}</high_issues>\n')
        fxml.write(f'    <medium_issues>{results["summary"]["medium"]}</medium_issues>\n')
        fxml.write(f'    <low_issues>{results["summary"]["low"]}</low_issues>\n')
        fxml.write('  </summary>\n')
        
        # Best practices
        fxml.write('  <best_practices>\n')
        fxml.write('    <encryption>Use AES-256 or ChaCha20, avoid DES/3DES</encryption>\n')
        fxml.write('    <hash>Use SHA-256, SHA-384, or SHA-512, avoid MD5/SHA-1</hash>\n')
        fxml.write('    <key_exchange>Use DH groups 14+ (2048+ bits) or ECP groups</key_exchange>\n')
        fxml.write('    <authentication>Use certificate-based authentication, avoid PSK</authentication>\n')
        fxml.write('    <protocol>Use IKEv2 only, disable IKEv1</protocol>\n')
        fxml.write('    <mode>Disable Aggressive Mode, use Main Mode only</mode>\n')
        fxml.write('  </best_practices>\n')
        
        # Services section
        fxml.write('  <services>\n')
        for ip, data in results["services"].items():
            ike_versions = []
            if vpns[ip].get("v1"):
                ike_versions.append("1")
            if vpns[ip].get("v2"):
                ike_versions.append("2")
            
            fxml.write(f'    <service ip="{ip}" ike_versions="{",".join(ike_versions)}">\n')
            fxml.write('      <flaws>\n')
            
            for i, flaw in enumerate(data["flaws"]):
                fxml.write(f'        <flaw id="{i}" severity="{flaw["severity"]}" description="{flaw["description"]}">')
                if flaw["data"]:
                    fxml.write(f'<![CDATA[{flaw["data"]}]]>')
                fxml.write('</flaw>\n')
            
            fxml.write('      </flaws>\n')
            fxml.write('    </service>\n')
        
        fxml.write('  </services>\n')
        fxml.write('</iker_results>\n')
    
    # Generate JSON report
    with open(args.json, "w", encoding="utf-8") as fjson:
        json.dump(results, fjson, indent=2, ensure_ascii=False)
    
    # Console summary
    logger.info("\n" + "="*60)
    logger.info("SCAN RESULTS SUMMARY")
    logger.info("="*60)
    logger.info(f"Total hosts scanned: {results['summary']['total_hosts']}")
    logger.info(f"Critical issues: {results['summary']['critical']}")
    logger.info(f"High severity issues: {results['summary']['high']}")
    logger.info(f"Medium severity issues: {results['summary']['medium']}")
    logger.info(f"Low severity issues: {results['summary']['low']}")
    logger.info("="*60)
    
    for ip, data in results["services"].items():
        logger.info(f"\nHost: {ip}")
        versions = []
        if vpns[ip].get("v1"):
            versions.append("IKEv1")
        if vpns[ip].get("v2"):
            versions.append("IKEv2")
        logger.info(f"  Supported versions: {', '.join(versions)}")
        logger.info(f"  Total issues: {len(data['flaws'])}")
        
        # Group by severity
        by_severity = {}
        for flaw in data["flaws"]:
            severity = flaw["severity"]
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(flaw["description"])
        
        for severity in ["critical", "high", "medium", "low"]:
            if severity in by_severity:
                logger.info(f"    {severity.upper()}: {len(by_severity[severity])}")
                for desc in by_severity[severity][:3]:  # Show first 3
                    logger.info(f"      - {desc}")
                if len(by_severity[severity]) > 3:
                    logger.info(f"      ... and {len(by_severity[severity]) - 3} more")
    
    logger.info(f"\nDetailed reports saved to:")
    logger.info(f"  XML: {args.xml}")
    logger.info(f"  JSON: {args.json}")

def main():
    """Main function"""
    welcome()
    
    # Check prerequisites
    if not check_privileges():
        logger.error("Root privileges required for raw socket operations")
        sys.exit(1)

    args, targets = get_arguments()
    
    if not check_ikescan():
        logger.error("ike-scan tool not found or not working")
        sys.exit(1)

    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"Starting iker scan at {start_time}")
    logger.info(f"Targets: {', '.join(targets)}")
    logger.info(f"Threads: {args.threads}")
    
    # Initialize data structures
    vpns = {}
    result_queue = queue.Queue()
    threads = []

    # Launch scanning threads
    for target in targets:
        if len(threads) >= args.threads:
            # Wait for some threads to complete
            for t in threads:
                t.join()
            threads = []
        
        t = threading.Thread(target=scan_target, args=(args, target, vpns, result_queue))
        threads.append(t)
        t.start()

    # Wait for remaining threads
    for t in threads:
        t.join()

    end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"Scan completed at {end_time}")

    if not vpns:
        logger.warning("No IKE services discovered")
        logger.info("This could mean:")
        logger.info("  - No IKE services are running on the target(s)")
        logger.info("  - Services are filtered by firewall")
        logger.info("  - Services are configured to ignore scans")
        sys.exit(1)

    # Generate reports
    generate_reports(args, vpns, start_time, end_time)
    
    logger.info("Scan completed successfully!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if VERBOSE:
            import traceback
            logger.error(traceback.format_exc())
        sys.exit(1)
