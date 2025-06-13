#!/usr/bin/env python3

import argparse
import json
import logging
import os
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Set

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Vulnerability descriptions
FLAWS = {
    "IKEV1": "Weak IKE version 1 supported (deprecated in favor of IKEv2)",
    "DISC": "The IKE service is discoverable, which should be restricted to authorized parties",
    "ENC_DES": "DES encryption detected - CRITICAL vulnerability (easily broken)",
    "ENC_3DES": "3DES encryption detected - deprecated and should be replaced with AES",
    "HASH_MD5": "MD5 hash algorithm detected - CRITICAL vulnerability (collision attacks possible)",
    "HASH_SHA1": "SHA1 hash algorithm detected - deprecated due to collision vulnerabilities",
    "DHG_1": "DH Group 1 (MODP-768) detected - CRITICAL vulnerability (insufficient key length)",
    "DHG_2": "DH Group 2 (MODP-1024) detected - weak DH group, should use Group 14+ (2048-bit+)",
    "AUTH_PSK": "Pre-shared key authentication - consider certificate-based authentication",
    "AGG_MODE": "Aggressive Mode supported - reveals identity and is vulnerable to offline attacks",
    "FING_VID": "Vendor ID fingerprinting possible via VID payload",
    "FING_BACKOFF": "Implementation fingerprinting possible via backoff pattern"
}

def run_command(cmd: List[str], timeout: int = 30) -> str:
    """Run a command with timeout"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        logger.warning(f"Command timed out: {' '.join(cmd)}")
        return ""
    except Exception as e:
        logger.error(f"Command failed: {' '.join(cmd)} - {e}")
        return ""

def check_ikev1(args: argparse.Namespace, vpns: Dict, ip: str):
    """Check for IKEv1 support"""
    logger.info(f"Discovering IKEv1 services for {ip}")
    output = run_command(["ike-scan", ip], timeout=10)
    
    if output and "Handshake returned" in output:
        logger.info(f"IKEv1 supported by {ip}")
        vpns[ip]["v1"] = True
        vpns[ip]["handshake"] = output
        
        # Extract and analyze vendor IDs from handshake
        fingerprint_vid(args, vpns, ip, output)

def check_ikev2(args: argparse.Namespace, vpns: Dict, ip: str):
    """Check for IKEv2 support"""
    logger.info(f"Checking IKEv2 support for {ip}")
    output = run_command(["ike-scan", "--ikev2", ip], timeout=10)
    
    logger.info(f"DEBUG: IKEv2 scan output for {ip}: {repr(output[:200])}")
    
    # Multiple patterns to detect IKEv2 response
    ikev2_patterns = [
        "IKE_SA_INIT response",
        "SA_INIT",
        "IKEv2",
        "returned notify",
        "Handshake returned",
        "HDR=",
        "SA="
    ]
    
    if output:
        for pattern in ikev2_patterns:
            if pattern in output:
                logger.info(f"IKEv2 supported by {ip} (detected via: {pattern})")
                vpns[ip]["v2"] = True
                vpns[ip]["ikev2_handshake"] = output
                return
    
    logger.info(f"IKEv2 not detected for {ip}")

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

def fingerprint_implementation(args: argparse.Namespace, vpns: Dict, ip: str):
    """Implementation fingerprinting via backoff analysis"""
    logger.info(f"Fingerprinting {ip} via backoff analysis")
    output = run_command(["ike-scan", "--showbackoff", ip], timeout=10)
    
    if output:
        vpns[ip]["showbackoff"] = output
    else:
        vpns[ip]["showbackoff"] = "Unknown"

def test_transforms(args: argparse.Namespace, vpns: Dict, ip: str):
    """Test supported encryption/hash algorithms"""
    logger.info(f"Testing encryption algorithms for {ip}")
    
    # Test multiple transform combinations
    transforms = [
        "1,1,1,1",      # DES-CBC, MD5, DH Group 1
        "1,2,1,1",      # DES-CBC, SHA1, DH Group 1  
        "5,1,1,1",      # 3DES-CBC, MD5, DH Group 1
        "5,2,1,1",      # 3DES-CBC, SHA1, DH Group 1
        "5,1,2,1",      # 3DES-CBC, MD5, DH Group 2
        "5,2,2,1",      # 3DES-CBC, SHA1, DH Group 2
        "7/128,1,2,1",  # AES-128, MD5, DH Group 2
        "7/128,2,2,1",  # AES-128, SHA1, DH Group 2
        "7/256,2,14,1", # AES-256, SHA1, DH Group 14
        "7/256,5,14,1", # AES-256, SHA256, DH Group 14
    ]
    
    results = []
    for i, transform in enumerate(transforms, 1):
        progress = (i / len(transforms)) * 100
        print(f"\r[{'█' * int(progress // 3.33):30}] {progress:.1f}% - Transform: {transform}", end="", flush=True)
        
        output = run_command(["ike-scan", "--trans", transform, ip], timeout=5)
        if output and "Handshake returned" in output:
            results.append((transform, output))
    
    print()  # New line after progress bar
    vpns[ip]["transforms"] = results

def test_aggressive_mode(args: argparse.Namespace, vpns: Dict, ip: str):
    """Test for Aggressive Mode support"""
    logger.info(f"Testing Aggressive Mode for {ip}")
    
    transforms = [
        "1,1,1,1",      # DES-CBC, MD5, DH Group 1
        "5,2,2,1",      # 3DES-CBC, SHA1, DH Group 2
        "7/128,2,14,1", # AES-128, SHA1, DH Group 14
        "7/256,5,14,1", # AES-256, SHA256, DH Group 14
    ]
    
    results = []
    for i, transform in enumerate(transforms, 1):
        progress = (i / len(transforms)) * 100
        print(f"\r[{'█' * int(progress // 3.33):30}] {progress:.1f}% - Transform: Aggressive: {transform}", end="", flush=True)
        
        output = run_command(["ike-scan", "--aggressive", "--trans", transform, ip], timeout=5)
        if output and "Handshake returned" in output:
            results.append((transform, output))
    
    print()  # New line after progress bar
    vpns[ip]["aggressive"] = results

def test_ikev2_features(args: argparse.Namespace, vpns: Dict, ip: str):
    """Test IKEv2-specific features"""
    logger.info(f"Testing IKEv2-specific features for {ip}")
    
    # Test for certificate request support
    output = run_command(["ike-scan", "--ikev2", "--certreq", ip], timeout=5)
    if output:
        vpns[ip]["ikev2_certreq"] = True

def analyze_security_flaws(vpns: Dict) -> Dict:
    """Analyze discovered configurations for security flaws"""
    logger.info("DEBUG: NEW analyze_security_flaws function started")
    logger.info("DEBUG: Line 2 - function executing")
    results = {"services": {}, "summary": {"total_hosts": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}}
    logger.info("DEBUG: Line 4 - results initialized")
    
    logger.info(f"DEBUG: vpns type: {type(vpns)}")
    logger.info(f"DEBUG: vpns keys: {list(vpns.keys())}")
    logger.info(f"DEBUG: vpns length: {len(vpns)}")
    logger.info("DEBUG: About to start for loop")
    
    for ip, data in vpns.items():
        logger.info(f"DEBUG: INSIDE FOR LOOP - Processing IP {ip}")
        results["services"][ip] = {"flaws": [], "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
        results["summary"]["total_hosts"] += 1
        
        logger.info(f"DEBUG: VPN data keys: {list(data.keys())}")
        
        # Service discovery (always flagged)
        flaw = {"description": FLAWS["DISC"], "severity": "medium", "data": data.get("handshake", "")}
        results["services"][ip]["flaws"].append(flaw)
        results["services"][ip]["severity_counts"]["medium"] += 1
        logger.info(f"DEBUG: Added service discovery flaw")
        
        # IKEv1 support
        if data.get("v1"):
            flaw = {"description": FLAWS["IKEV1"], "severity": "high", "data": ""}
            results["services"][ip]["flaws"].append(flaw)
            results["services"][ip]["severity_counts"]["high"] += 1
            logger.info(f"DEBUG: Added IKEv1 flaw")
        
        # Check VID data for algorithms 
        logger.info(f"DEBUG: About to check VID data for {ip}")
        logger.info(f"DEBUG: VID data: {data.get('vid', [])}")
        for vid_name, vid_handshake in data.get("vid", []):
            logger.info(f"DEBUG: Processing VID: {vid_name}")
            logger.info(f"DEBUG: VID handshake content: {repr(vid_handshake[:200])}")
            
            if vid_handshake and "3des" in vid_handshake.lower():
                logger.info(f"DEBUG: FOUND 3DES - Adding flaw")
                flaw = {"description": f"{FLAWS['ENC_3DES']} (detected in VID)", "severity": "high", "data": vid_handshake}
                results["services"][ip]["flaws"].append(flaw)
                results["services"][ip]["severity_counts"]["high"] += 1
            
            if vid_handshake and "md5" in vid_handshake.lower():
                logger.info(f"DEBUG: FOUND MD5 - Adding flaw")
                flaw = {"description": f"{FLAWS['HASH_MD5']} (detected in VID)", "severity": "critical", "data": vid_handshake}
                results["services"][ip]["flaws"].append(flaw)
                results["services"][ip]["severity_counts"]["critical"] += 1
            
            if vid_handshake and "modp1024" in vid_handshake.lower():
                logger.info(f"DEBUG: FOUND MODP1024 - Adding flaw")
                flaw = {"description": f"{FLAWS['DHG_2']} (detected in VID)", "severity": "high", "data": vid_handshake}
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
        
        # Update summary counts
        for severity, count in results["services"][ip]["severity_counts"].items():
            results["summary"][severity] += count
        
        logger.info(f"DEBUG: Completed processing {ip}, current counts: {results['services'][ip]['severity_counts']}")
    
    logger.info(f"DEBUG: NEW analyze_security_flaws completed, final counts: {results['summary']}")
    return results

def scan_target(args: argparse.Namespace, ip: str) -> Dict:
    """Comprehensive scan of a single target"""
    logger.info(f"Starting comprehensive scan of {ip}")
    
    vpn_data = {ip: {"v1": False, "v2": False, "vid": [], "transforms": [], "aggressive": []}}
    
    # Check IKE version support
    check_ikev1(args, vpn_data, ip)
    check_ikev2(args, vpn_data, ip)
    
    if not vpn_data[ip]["v1"] and not vpn_data[ip]["v2"]:
        logger.warning(f"No IKE services found on {ip}")
        return vpn_data
    
    # Analyze discovered service
    logger.info(f"Analyzing discovered service at {ip}")
    
    # Implementation fingerprinting
    fingerprint_implementation(args, vpn_data, ip)
    
    # Transform testing
    test_transforms(args, vpn_data, ip)
    
    # Aggressive mode testing
    test_aggressive_mode(args, vpn_data, ip)
    
    # IKEv2 specific tests
    if vpn_data[ip]["v2"]:
        test_ikev2_features(args, vpn_data, ip)
    
    logger.info(f"Completed analysis of {ip}")
    return vpn_data

def generate_xml_report(results: Dict, filename: str):
    """Generate XML report"""
    root = ET.Element("iker_scan")
    
    # Scan info
    scan_info = ET.SubElement(root, "scan_info")
    ET.SubElement(scan_info, "start_time").text = results["scan_info"]["start_time"]
    ET.SubElement(scan_info, "end_time").text = results["scan_info"]["end_time"]
    ET.SubElement(scan_info, "total_hosts").text = str(results["summary"]["total_hosts"])
    
    # Summary
    summary = ET.SubElement(root, "summary")
    for severity in ["critical", "high", "medium", "low"]:
        ET.SubElement(summary, severity).text = str(results["summary"][severity])
    
    # Services
    services = ET.SubElement(root, "services")
    for ip, service_data in results["services"].items():
        service = ET.SubElement(services, "service", ip=ip)
        
        flaws_elem = ET.SubElement(service, "flaws")
        for flaw in service_data["flaws"]:
            flaw_elem = ET.SubElement(flaws_elem, "flaw", severity=flaw["severity"])
            flaw_elem.text = flaw["description"]
    
    tree = ET.ElementTree(root)
    tree.write(filename, encoding="utf-8", xml_declaration=True)

def generate_reports(args: argparse.Namespace, vpns: Dict, start_time: str, end_time: str):
    """Generate XML and JSON reports"""
    logger.info(f"DEBUG: NEW generate_reports called with vpns: {list(vpns.keys())}")
    
    results = analyze_security_flaws(vpns)
    
    logger.info(f"DEBUG: NEW analyze_security_flaws returned: {results['summary']}")
    
    # Add metadata
    results["scan_info"] = {
        "start_time": start_time,
        "end_time": end_time,
        "targets": list(vpns.keys())
    }
    
    # Generate reports
    xml_file = "iker_output.xml"
    json_file = "iker_output.json"
    
    generate_xml_report(results, xml_file)
    
    with open(json_file, "w") as f:
        json.dump(results, f, indent=2)
    
    # Console summary
    logger.info("")
    logger.info("=" * 60)
    logger.info("SCAN RESULTS SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Total hosts scanned: {results['summary']['total_hosts']}")
    logger.info(f"Critical issues: {results['summary']['critical']}")
    logger.info(f"High severity issues: {results['summary']['high']}")
    logger.info(f"Medium severity issues: {results['summary']['medium']}")
    logger.info(f"Low severity issues: {results['summary']['low']}")
    logger.info("=" * 60)
    logger.info("")
    
    # Detailed per-host results
    for ip, service_data in results["services"].items():
        logger.info(f"Host: {ip}")
        versions = []
        vpn_data = vpns.get(ip, {})
        if vpn_data.get("v1"): versions.append("IKEv1")
        if vpn_data.get("v2"): versions.append("IKEv2")
        logger.info(f"  Supported versions: {', '.join(versions)}")
        
        total_flaws = sum(service_data["severity_counts"].values())
        logger.info(f"  Total issues: {total_flaws}")
        
        for severity in ["critical", "high", "medium", "low"]:
            count = service_data["severity_counts"][severity]
            if count > 0:
                logger.info(f"    {severity.upper()}: {count}")
                for flaw in service_data["flaws"]:
                    if flaw["severity"] == severity:
                        logger.info(f"      - {flaw['description']}")
        logger.info("")
    
    logger.info("Detailed reports saved to:")
    logger.info(f"  XML: {xml_file}")
    logger.info(f"  JSON: {json_file}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="iker v2.1 - IPsec VPN Security Scanner")
    parser.add_argument("targets", nargs="+", help="Target IP addresses or ranges")
    parser.add_argument("-t", "--threads", type=int, default=1, help="Number of threads (default: 1)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout for individual scans (default: 10)")
    
    args = parser.parse_args()
    
    logger.info("iker v2.1 - IPsec VPN Security Scanner")
    logger.info("By Julio Gomez (jgo@portcullis-security.com), updated by xAI")
    logger.info("Enhanced IKEv2 detection and modern cryptographic analysis")
    
    # Check for ike-scan
    try:
        result = subprocess.run(["which", "ike-scan"], capture_output=True, text=True)
        if result.returncode == 0:
            logger.info(f"ike-scan found: {result.stdout.strip()}")
        else:
            logger.error("ike-scan not found. Please install ike-scan.")
            return 1
    except Exception as e:
        logger.error(f"Error checking for ike-scan: {e}")
        return 1
    
    start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"Starting iker scan at {start_time}")
    logger.info(f"Targets: {', '.join(args.targets)}")
    logger.info(f"Threads: {args.threads}")
    
    # Scan targets
    all_vpns = {}
    
    if args.threads == 1:
        # Single-threaded scanning
        for target in args.targets:
            vpn_data = scan_target(args, target)
            all_vpns.update(vpn_data)
    else:
        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_target = {executor.submit(scan_target, args, target): target for target in args.targets}
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    vpn_data = future.result()
                    all_vpns.update(vpn_data)
                except Exception as e:
                    logger.error(f"Scan failed for {target}: {e}")
    
    end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"Scan completed at {end_time}")
    
    # Generate reports
    generate_reports(args, all_vpns, start_time, end_time)
    
    logger.info("Scan completed successfully!")
    return 0

if __name__ == "__main__":
    exit(main())
