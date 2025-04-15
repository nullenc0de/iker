#!/usr/bin/env python3
'''
iker.py script courtesy of Portcullis Security

https://labs.portcullis.co.uk/tools/iker/

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

VERSION = "2.0"

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

# Algorithm lists
ENCLIST = ['1', '5', '7/128', '7/192', '7/256', '20']  # DES, 3DES, AES, ChaCha20
HASHLIST = ['1', '2', '5', '6']  # MD5, SHA1, SHA256, SHA512
AUTHLIST = ['1', '3', '64221', '65001']  # PSK, RSA Sig, Hybrid, XAUTH
GROUPLIST = ['1', '2', '5', '14', '19', '20']  # DH groups including ECP

FULLENCLIST = ['1', '2', '3', '4', '5', '6', '7/128', '7/192', '7/256', '8', '20', '24']
FULLENCLISTv2 = ['1', '5', '7/128', '7/192', '7/256', '12', '13', '14', '18', '19', '20', '24']
FULLHASHLIST = ['1', '2', '3', '4', '5', '6']
FULLHASHLISTv2 = ['1', '2', '5', '6', '7', '8']
FULLAUTHLIST = ['1', '3', '4', '5', '6', '7', '8', '9', '10', '11', '64221', '65001']
FULLGROUPLIST = ['1', '2', '5', '14', '15', '16', '19', '20', '21', '23', '24']

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
    "ENC_DES": "Weak encryption: DES (broken, <128-bit key)",
    "ENC_3DES": "Weak encryption: 3DES (vulnerable to attacks)",
    "ENC_IDEA": "Weak encryption: IDEA (outdated)",
    "ENC_BLOW": "Weak encryption: Blowfish (variable security)",
    "ENC_RC5": "Weak encryption: RC5 (outdated)",
    "ENC_CAST": "Weak encryption: CAST (outdated)",
    "HASH_MD5": "Weak hash: MD5 (cryptographically broken)",
    "HASH_SHA1": "Weak hash: SHA-1 (cryptographically broken)",
    "DHG_1": "Weak DH group: MODP-768 (insufficient key strength)",
    "DHG_2": "Weak DH group: MODP-1024 (insufficient key strength)",
    "DHG_5": "Weak DH group: MODP-1536 (insufficient key strength)",
    "AUTH_PSK": "Weak authentication: PSK (vulnerable to brute-forcing)",
    "AUTH_RSA_SIG": "Moderate authentication: RSA signatures (depends on key strength)",
    "AUTH_HYBRID": "Weak authentication: Hybrid mode (potential vulnerabilities)",
    "AGGR": "Aggressive Mode enabled (vulnerable to attacks)",
    "AGGR_GRP_NO_ENC": "Aggressive Mode leaks group name unencrypted",
    "CID_ENUM": "Client ID enumeration possible",
    "NAT_T_MISCONFIG": "NAT Traversal misconfiguration detected",
    "FRAG_VULN": "IKE fragmentation vulnerability detected"
}

def welcome():
    logger.info(f"iker v{VERSION} - IPsec VPN Security Scanner")
    logger.info("By Julio Gomez (jgo@portcullis-security.com), updated by xAI")

def check_privileges() -> bool:
    return os.geteuid() == 0

def check_ikescan() -> bool:
    try:
        result = subprocess.run(
            [FULLIKESCANPATH, "--version"],
            capture_output=True,
            text=True,
            check=True
        )
        if "ike-scan" in result.stderr.lower() or result.stdout.lower():
            return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("ike-scan not found or incompatible. Specify path with --ikepath.")
        return False
    return False

def get_arguments() -> Tuple[argparse.Namespace, List[str]]:
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
    parser.add_argument("--encalgs", type=str, default="1 5 7/128 7/256 20", help="Encryption algorithms")
    parser.add_argument("--hashalgs", type=str, default="1 2 5 6", help="Hash algorithms")
    parser.add_argument("--authmethods", type=str, default="1 3 64221 65001", help="Auth methods")
    parser.add_argument("--kegroups", type=str, default="1 2 5 14 19 20", help="DH groups")
    parser.add_argument("--fullalgs", action="store_true", help="Test all known algorithms")
    parser.add_argument("--ikepath", type=str, default=FULLIKESCANPATH, help="ike-scan path")
    parser.add_argument("-c", "--clientids", type=str, help="Client ID dictionary file")
    parser.add_argument("-n", "--nofingerprint", action="store_true", help="Skip fingerprinting")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of scanning threads")
    parser.add_argument("--natt", action="store_true", help="Test NAT-T configurations")
    parser.add_argument("--frag", action="store_true", help="Test IKE fragmentation")

    args = parser.parse_args()
    targets = []

    if args.target and re.match(r'\d+\.\d+\.\d+\.\d+', args.target):
        targets.append(args.target)
    elif args.target:
        logger.error("Target must be a valid IP or CIDR")
        parser.print_help()
        sys.exit(1)

    if args.input:
        try:
            with open(args.input, "r") as f:
                targets.extend(line.strip() for line in f if line.strip())
        except IOError as e:
            logger.error(f"Cannot read input file {args.input}: {e}")
            sys.exit(1)

    if not targets:
        logger.error("Specify a target or input file")
        parser.print_help()
        sys.exit(1)

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
    try:
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
    if ADAPTIVE_DELAY:
        jitter = random.uniform(0.5, 1.5)
        time.sleep((base_delay * jitter) / 1000.0)
    elif base_delay:
        time.sleep(base_delay / 1000.0)

def update_progress_bar(current: int, total: int, transform: str):
    width = 20
    percent = (current / total) * 100
    filled = int(width * current // total)
    bar = '=' * filled + '.' * (width - filled)
    sys.stdout.write(f"\r[{bar}] {percent:.1f}% - Transform: {transform}")
    sys.stdout.flush()

def discovery(args: argparse.Namespace, target: str, vpns: Dict, q: queue.Queue):
    logger.info(f"Discovering IKE services for {target}")
    command = f"{FULLIKESCANPATH} -M {target}"
    stdout, stderr, rc = run_command(command)

    ip = None
    info = []
    for line in stdout.splitlines():
        if not line.strip() or "Starting ike-scan" in line or "Ending ike-scan" in line:
            continue
        if re.match(r'\d+\.\d+\.\d+\.\d+', line.split()[0]):
            if info:
                vpns[ip] = {"handshake": "\n".join(info), "v1": True}
                q.put((ip, "v1", True))
                logger.info(f"IKEv1 supported by {ip}")
            ip = line.split()[0]
            info = [line]
        else:
            info.append(line)

    if info and ip:
        vpns[ip] = {"handshake": "\n".join(info), "v1": True}
        q.put((ip, "v1", True))
        logger.info(f"IKEv1 supported by {ip}")

def check_ikev2(args: argparse.Namespace, target: str, vpns: Dict, q: queue.Queue):
    logger.info(f"Checking IKEv2 support for {target}")
    command = f"{FULLIKESCANPATH} -2 -M {target}"
    stdout, stderr, rc = run_command(command)

    ip = None
    info = []
    for line in stdout.splitlines():
        if not line.strip() or "Starting ike-scan" in line or "Ending ike-scan" in line:
            continue
        if re.match(r'\d+\.\d+\.\d+\.\d+', line.split()[0]):
            if info:
                vpns[ip]["v2"] = True
                q.put((ip, "v2", True))
                logger.info(f"IKEv2 supported by {ip}")
            ip = line.split()[0]
            info = [line]
        else:
            info.append(line)

    if info and ip:
        vpns[ip]["v2"] = True
        q.put((ip, "v2", True))
        logger.info(f"IKEv2 supported by {ip}")

def fingerprint_vid(args: argparse.Namespace, vpns: Dict, ip: str, handshake: str):
    if "vid" not in vpns[ip]:
        vpns[ip]["vid"] = []

    transform = ""
    vid = ""
    for line in handshake.splitlines():
        if "SA=" in line:
            transform = line.strip()[4:-1]
        if "VID=" in line and "(" in line and ")" in line and "draft-ietf" not in line:
            vid = line[line.index('(')+1:line.index(')')]

    if vid and vid not in [v[0] for v in vpns[ip]["vid"]]:
        vpns[ip]["vid"].append((vid, handshake))
        logger.info(f"Vendor ID for {ip}: {vid} (Transform: {transform})")

def fingerprint_backoff(args: argparse.Namespace, vpns: Dict, ip: str, transform: str = ""):
    if args.nofingerprint:
        return

    logger.info(f"Fingerprinting {ip} via backoff")
    cmd = f"{FULLIKESCANPATH} --showbackoff {f'--trans={transform}' if transform else ''} {ip}"
    stdout, _, _ = run_command(cmd)

    for line in stdout.splitlines():
        if "Implementation guess:" in line:
            vendor = line.split("Implementation guess:")[1].strip()
            if vendor.lower() != "unknown":
                vpns[ip]["showbackoff"] = vendor
                logger.info(f"Implementation guessed for {ip}: {vendor}")
                break
    else:
        vpns[ip]["showbackoff"] = "Unknown"
        logger.warning(f"Could not fingerprint {ip}")

def check_encryption_algs(args: argparse.Namespace, vpns: Dict, ip: str, q: queue.Queue):
    total = len(ENCLIST) * len(HASHLIST) * len(AUTHLIST) * len(GROUPLIST)
    current = 0
    vpns[ip]["transforms"] = []

    for enc in random.sample(ENCLIST, len(ENCLIST)):
        for hsh in random.sample(HASHLIST, len(HASHLIST)):
            for auth in random.sample(AUTHLIST, len(AUTHLIST)):
                for group in random.sample(GROUPLIST, len(GROUPLIST)):
                    current += 1
                    transform = f"{enc},{hsh},{auth},{group}"
                    update_progress_bar(current, total, transform)
                    cmd = f"{FULLIKESCANPATH} -M --trans={transform} {ip}"
                    stdout, _, _ = run_command(cmd)

                    info = []
                    new = False
                    for line in stdout.splitlines():
                        if "Starting ike-scan" in line or "Ending ike-scan" in line or not line.strip():
                            continue
                        info.append(line)
                        if "SA=" in line:
                            new = True
                            trans = line[4:-1]
                            logger.info(f"Transform found for {ip}: {trans}")

                    if new:
                        vpns[ip]["transforms"].append((transform, trans, "\n".join(info)))
                        q.put((ip, "transform", trans))
                        fingerprint_vid(args, vpns, ip, "\n".join(info))
                        if not vpns[ip].get("showbackoff"):
                            fingerprint_backoff(args, vpns, ip, transform)

                    adaptive_sleep(DELAY)

def check_aggressive(args: argparse.Namespace, vpns: Dict, ip: str, q: queue.Queue):
    total = len(ENCLIST) * len(HASHLIST) * len(AUTHLIST) * len(GROUPLIST)
    current = 0
    vpns[ip]["aggressive"] = []

    for enc in random.sample(ENCLIST, len(ENCLIST)):
        for hsh in random.sample(HASHLIST, len(HASHLIST)):
            for auth in random.sample(AUTHLIST, len(AUTHLIST)):
                for group in random.sample(GROUPLIST, len(GROUPLIST)):
                    current += 1
                    transform = f"{enc},{hsh},{auth},{group}"
                    update_progress_bar(current, total, transform)
                    handshake_file = f"{ip}_handshake.txt"
                    cmd = f"{FULLIKESCANPATH} -M --aggressive -P{handshake_file} --trans={transform} {ip}"
                    stdout, _, _ = run_command(cmd)

                    info = []
                    new = False
                    for line in stdout.splitlines():
                        if "Starting ike-scan" in line or "Ending ike-scan" in line or not line.strip():
                            continue
                        info.append(line)
                        if "SA=" in line:
                            new = True
                            trans = line[4:-1]
                            logger.info(f"Aggressive mode supported by {ip}: {trans}")

                    if new:
                        vpns[ip]["aggressive"].append((transform, trans, "\n".join(info)))
                        q.put((ip, "aggressive", trans))
                        fingerprint_vid(args, vpns, ip, "\n".join(info))
                        if not vpns[ip].get("showbackoff"):
                            fingerprint_backoff(args, vpns, ip, transform)

                    adaptive_sleep(DELAY)

def enumerate_client_ids(args: argparse.Namespace, vpns: Dict, ip: str, q: queue.Queue):
    if not args.clientids or not vpns[ip].get("aggressive"):
        return

    logger.info(f"Enumerating client IDs for {ip}")
    transform = vpns[ip]["aggressive"][0][0]
    invalid_ids = ["badgroupiker123", "badgroupiker456", "badgroupiker789"]
    invalid_msgs = []

    for cid in invalid_ids:
        cmd = f"{FULLIKESCANPATH} --aggressive --trans={transform} --id={cid} {ip}"
        stdout, _, _ = run_command(cmd)
        msg = re.sub(r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', stdout.strip())
        invalid_msgs.append(msg)
        adaptive_sleep(DELAY)

    invalid_msg = max(set(invalid_msgs), key=invalid_msgs.count) if invalid_msgs else ""
    if not invalid_msg:
        logger.warning(f"Could not determine invalid client ID response for {ip}")
        return

    try:
        with open(args.clientids, "r") as f:
            client_ids = [line.strip() for line in f if line.strip()]
        random.shuffle(client_ids)

        vpns[ip]["clientids"] = []
        for cid in client_ids:
            cmd = f"{FULLIKESCANPATH} --aggressive --trans={transform} --id={cid} {ip}"
            stdout, _, _ = run_command(cmd)
            msg = re.sub(r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', stdout.strip())
            if msg and msg != invalid_msg:
                vpns[ip]["clientids"].append(cid)
                q.put((ip, "clientid", cid))
                logger.info(f"Valid client ID found for {ip}: {cid}")
            adaptive_sleep(DELAY)
    except IOError as e:
        logger.error(f"Cannot read client ID file {args.clientids}: {e}")

def check_natt(args: argparse.Namespace, vpns: Dict, ip: str, q: queue.Queue):
    if not args.natt:
        return

    logger.info(f"Testing NAT-T for {ip}")
    cmd = f"{FULLIKESCANPATH} --nat-t {ip}"
    stdout, _, _ = run_command(cmd)
    if "NAT-T" in stdout:
        vpns[ip]["natt"] = True
        q.put((ip, "natt", True))
        logger.warning(f"NAT-T enabled on {ip}, potential misconfiguration")
    else:
        vpns[ip]["natt"] = False

def check_fragmentation(args: argparse.Namespace, vpns: Dict, ip: str, q: queue.Queue):
    if not args.frag:
        return

    logger.info(f"Testing IKE fragmentation for {ip}")
    cmd = f"{FULLIKESCANPATH} --trans=7/256,5,1,14 --frag {ip}"
    stdout, _, _ = run_command(cmd)
    if "Fragmentation" in stdout:
        vpns[ip]["frag"] = True
        q.put((ip, "frag", True))
        logger.warning(f"IKE fragmentation supported on {ip}, potential DoS risk")
    else:
        vpns[ip]["frag"] = False

def scan_target(args: argparse.Namespace, target: str, vpns: Dict, result_queue: queue.Queue):
    try:
        discovery(args, target, vpns, result_queue)
        check_ikev2(args, target, vpns, result_queue)
        for ip in vpns:
            fingerprint_vid(args, vpns, ip, vpns[ip]["handshake"])
            fingerprint_backoff(args, vpns, ip)
            check_encryption_algs(args, vpns, ip, result_queue)
            check_aggressive(args, vpns, ip, result_queue)
            enumerate_client_ids(args, vpns, ip, result_queue)
            check_natt(args, vpns, ip, result_queue)
            check_fragmentation(args, vpns, ip, result_queue)
    except Exception as e:
        logger.error(f"Error scanning {target}: {e}")

def parse_results(args: argparse.Namespace, vpns: Dict, start_time: str, end_time: str):
    results = {"services": {}, "best_practices": {
        "encryption": "Use AES-256 or stronger, avoid DES/3DES",
        "hash": "Use SHA-256 or stronger, avoid MD5/SHA-1",
        "key_exchange": "Use DH groups >= 2048 bits or ECP",
        "authentication": "Use mutual authentication, avoid PSK"
    }}

    with open(args.xml, "w") as fxml:
        fxml.write(f'<?xml version="1.0" encoding="UTF-8"?>\n')
        fxml.write(f'<?time start="{start_time}" end="{end_time}"?>\n')
        fxml.write("<iker_results>\n")
        fxml.write("<best_practices>\n")
        for k, v in results["best_practices"].items():
            fxml.write(f'\t<{k}>{v}</{k}>\n')
        fxml.write("</best_practices>\n")
        fxml.write("<services>\n")

        for ip, data in vpns.items():
            results["services"][ip] = {"flaws": []}
            fxml.write(f'\t<service ip="{ip}">\n\t\t<flaws>\n')
            flawid = 0

            # Discovery
            results["services"][ip]["flaws"].append(FLAWS["DISC"])
            fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["DISC"]}"><![CDATA[{data["handshake"]}]]></flaw>\n')
            flawid += 1

            # IKEv1
            if data.get("v1"):
                results["services"][ip]["flaws"].append(FLAWS["IKEV1"])
                fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["IKEV1"]}"></flaw>\n')
                flawid += 1

            # VID Fingerprinting
            for vid, hshk in data.get("vid", []):
                results["services"][ip]["flaws"].append(f"{FLAWS['FING_VID']}: {vid}")
                fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["FING_VID"]}" value="{vid}"><![CDATA[{hshk}]]></flaw>\n')
                flawid += 1

            # Backoff Fingerprinting
            if data.get("showbackoff") and data["showbackoff"] != "Unknown":
                results["services"][ip]["flaws"].append(f"{FLAWS['FING_BACKOFF']}: {data['showbackoff']}")
                fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["FING_BACKOFF"]}" value="{data["showbackoff"]}"></flaw>\n')
                flawid += 1

            # Transforms
            for transform, desc, info in data.get("transforms", []):
                if "Enc=DES" in desc:
                    results["services"][ip]["flaws"].append(FLAWS["ENC_DES"])
                    fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["ENC_DES"]}" value="{desc}"><![CDATA[{info}]]></flaw>\n')
                    flawid += 1
                if "Enc=3DES" in desc:
                    results["services"][ip]["flaws"].append(FLAWS["ENC_3DES"])
                    fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["ENC_3DES"]}" value="{desc}"><![CDATA[{info}]]></flaw>\n')
                    flawid += 1
                if "Hash=MD5" in desc:
                    results["services"][ip]["flaws"].append(FLAWS["HASH_MD5"])
                    fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["HASH_MD5"]}" value="{desc}"><![CDATA[{info}]]></flaw>\n')
                    flawid += 1
                if "Hash=SHA1" in desc:
                    results["services"][ip]["flaws"].append(FLAWS["HASH_SHA1"])
                    fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["HASH_SHA1"]}" value="{desc}"><![CDATA[{info}]]></flaw>\n')
                    flawid += 1
                if "Group=1" in desc:
                    results["services"][ip]["flaws"].append(FLAWS["DHG_1"])
                    fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["DHG_1"]}" value="{desc}"><![CDATA[{info}]]></flaw>\n')
                    flawid += 1
                if "Group=2" in desc:
                    results["services"][ip]["flaws"].append(FLAWS["DHG_2"])
                    fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["DHG_2"]}" value="{desc}"><![CDATA[{info}]]></flaw>\n')
                    flawid += 1
                if "Group=5" in desc:
                    results["services"][ip]["flaws"].append(FLAWS["DHG_5"])
                    fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["DHG_5"]}" value="{desc}"><![CDATA[{info}]]></flaw>\n')
                    flawid += 1
                if "Auth=PSK" in desc:
                    results["services"][ip]["flaws"].append(FLAWS["AUTH_PSK"])
                    fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["AUTH_PSK"]}" value="{desc}"><![CDATA[{info}]]></flaw>\n')
                    flawid += 1

            # Aggressive Mode
            for transform, desc, info in data.get("aggressive", []):
                results["services"][ip]["flaws"].append(f"{FLAWS['AGGR']}: {desc}")
                fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["AGGR"]}" value="{desc}"><![CDATA[{info}]]></flaw>\n')
                flawid += 1
                results["services"][ip]["flaws"].append(FLAWS["AGGR_GRP_NO_ENC"])
                fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["AGGR_GRP_NO_ENC"]}"></flaw>\n')
                flawid += 1

            # Client IDs
            if data.get("clientids"):
                cids = ", ".join(data["clientids"])
                results["services"][ip]["flaws"].append(f"{FLAWS['CID_ENUM']}: {cids}")
                fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["CID_ENUM"]}" value="{cids}"></flaw>\n')
                flawid += 1

            # NAT-T
            if data.get("natt"):
                results["services"][ip]["flaws"].append(FLAWS["NAT_T_MISCONFIG"])
                fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["NAT_T_MISCONFIG"]}"></flaw>\n')
                flawid += 1

            # Fragmentation
            if data.get("frag"):
                results["services"][ip]["flaws"].append(FLAWS["FRAG_VULN"])
                fxml.write(f'\t\t\t<flaw id="{flawid}" description="{FLAWS["FRAG_VULN"]}"></flaw>\n')
                flawid += 1

            fxml.write("\t\t</flaws>\n\t</service>\n")

        fxml.write("</services>\n</iker_results>\n")

    with open(args.json, "w") as fjson:
        json.dump(results, fjson, indent=2)

    logger.info("\nResults Summary:")
    for ip, data in results["services"].items():
        logger.info(f"\nIP {ip}:")
        for flaw in data["flaws"]:
            logger.info(f"  - {flaw}")

def main():
    welcome()
    if not check_privileges():
        logger.error("Root privileges required")
        sys.exit(1)

    args, targets = get_arguments()
    if not check_ikescan():
        sys.exit(1)

    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
    logger.info(f"Starting iker at {start_time}")

    vpns = {}
    result_queue = queue.Queue()
    threads = []

    for target in targets:
        t = threading.Thread(target=scan_target, args=(args, target, vpns, result_queue))
        threads.append(t)
        t.start()
        if len(threads) >= args.threads:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

    end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
    logger.info(f"Finished at {end_time}")

    if not vpns:
        logger.warning("No IKE services found")
        sys.exit(1)

    parse_results(args, vpns, start_time, end_time)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Terminated by user")
        sys.exit(0)
