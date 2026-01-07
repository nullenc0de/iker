#!/usr/bin/env python
'''
iker.py script courtesy of Portcullis Security

https://labs.portcullis.co.uk/tools/iker/

Modifications from original v1.0 script:
	Added shebang for python binary above

Modifications from v1.1 script:
	Added all known algorithms
	Added Python2+ and Python3+ support
	Updated flaws with industry standards
	Removed flaws stating static risk as risk is dynamic
	Fixed grammar and updated technical terms (key exchange over Diffie-Hellman)
'''
###############################################################################
# iker.py
#
# This tool can be used to analyze the security of a IPsec based VPN.
#
# This script is under GPL v3 License:
#
#                                http://www.gnu.org/licenses/gpl-3.0.html
#
# From a IP address/range or a list of them, iker.py uses ike-scan to
# look for common misconfiguration in IKE implementations.
#
#
# Original author: Julio Gomez Ortega (JGO@portcullis-security.com)
#
###############################################################################

from sys import exit, stdout
from os import geteuid
import os
import io
import json
import subprocess
import argparse
import re
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import localtime, strftime, sleep


###############################################################################

# iker version
VERSION = "1.3-enhanced"

# ike-scan full path (--sport=0 uses random source port to avoid binding to 500)
FULLIKESCANPATH = "ike-scan --sport=0"

# Verbose flag (default False)
VERBOSE = False

# Encryption algorithms: DES, Triple-DES, AES/128, AES/192 and AES/256
ENCLIST = []

# Hash algorithms: MD5 and SHA1
HASHLIST = []

# Authentication methods: Pre-Shared Key, RSA Signatures, Hybrid Mode and XAUTH
AUTHLIST = []

# Diffie-Hellman groups: 1, 2 and 5
GROUPLIST = []

# Full algorithms lists - Updated with modern algorithms
FULLENCLIST = ['1', '2', '3', '4', '5', '6', '7/128', '7/192', '7/256', '8', '9', '12', '13', '20', '28', '65001', '65002', '65004', '65005']
FULLENCLISTv2 = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '12', '13', '14', '15', '16', '18', '19', '20', '23', '28']
FULLHASHLIST = ['1', '2', '3', '4', '5', '6', '7', '8']
FULLHASHLISTv2 = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12']
FULLAUTHLIST = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '128', '64221', '64223', '65001', '65003', '65005', '65007', '65009']
FULLGROUPLIST = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '30', '31']

# Modern algorithm classifications
MODERN_SECURE_ENCS = ['7/256', '20', '28']  # AES-256, ChaCha20
MODERN_SECURE_HASHES = ['4', '5', '6', '7', '8']  # SHA-256, SHA-384, SHA-512
MODERN_SECURE_GROUPS = ['14', '15', '16', '17', '18', '19', '20', '21']  # 2048-bit+ and ECC groups


# XML Output
XMLOUTPUT = "iker_output.xml"

# Client IDs dictionary
CLIENTIDS = ""

# Hashcat output directory
HASHCAT_DIR = ""

# Delay between requests
DELAY = 0

# Default VPN group names for enumeration
DEFAULT_GROUPS = [
    # Generic common names
    "vpn", "VPN", "GroupVPN", "groupvpn", "GROUPVPN",
    "default", "Default", "DEFAULT",
    "ipsec", "IPSec", "IPSEC",
    "remote", "Remote", "REMOTE",
    "client", "Client", "CLIENT",
    "mobile", "Mobile", "MOBILE",
    "users", "Users", "USERS",
    "employees", "Employees", "staff", "Staff",
    "admin", "Admin", "ADMIN", "ADMINVPN",
    "test", "Test", "TEST",
    "guest", "Guest", "partner", "Partner",
    "vendor", "Vendor", "contractor", "Contractor",

    # SonicWall specific
    "WAN GroupVPN", "WANGROUPVPN", "WLAN GroupVPN",
    "LocalDomain", "NetExtender", "GlobalVPN",
    "SSLVPN", "SSL-VPN", "SonicWALL",

    # Cisco specific
    "cisco", "Cisco", "CISCO",
    "anyconnect", "AnyConnect", "ANYCONNECT",
    "AnyConnect_Default", "ANYCONNECT_DEFAULT",
    "ANYConnectGroup", "ANYProfile", "ANYTUNNEL",
    "AC_Client", "DefaultRAGroup", "DefaultWEBVPNGroup",

    # Fortinet specific
    "fortigate", "FortiGate", "fortinet", "Fortinet", "FORTINET",
    "FortiClient", "FGTVPN",

    # Palo Alto
    "GP", "GlobalProtect", "GLOBALPROTECT",
    "PaloAlto", "PAN-GP",

    # CheckPoint
    "checkpoint", "CheckPoint", "CHECKPOINT",
    "RemoteAccess", "CPVPN",

    # Juniper
    "juniper", "Juniper", "JUNIPER",
    "JuniperVPN", "JNPR",

    # Generic organizational
    "main", "Main", "MAIN",
    "primary", "Primary", "PRIMARY",
    "office", "Office", "OFFICE",
    "home", "Home", "HOME",
    "internal", "Internal", "INTERNAL",
    "external", "External", "EXTERNAL",
    "corporate", "Corporate", "CORPORATE",
    "sales", "Sales", "SALES",
    "engineering", "Engineering", "ENGINEERING",
    "it", "IT", "ITAdmin", "IT-VPN",
    "finance", "Finance", "FINANCE",
    "hr", "HR", "HumanResources",
    "executive", "Executive", "EXECUTIVE",
    "management", "Management", "MANAGEMENT",

    # Common patterns from Shodan data
    "SSLVPN_TUNNEL", "SSL_VPN", "SSLVPN_Users",
    "Remote_Access", "RemoteUsers", "Remote-Access",
    "Site-to-Site", "SiteToSite", "S2S",
    "L2TP", "L2TP-VPN", "PPTP",
    "IKEv2", "IKEv2-VPN",
    "MobileVPN", "Mobile-VPN", "MobileUsers",
    "BYOD", "BYOD-VPN",
    "Guest-VPN", "GuestAccess", "GuestNetwork",
    "Contractor-VPN", "ContractorAccess",
    "Vendor-VPN", "VendorAccess", "ThirdParty",
    "Partner-VPN", "PartnerAccess",
    "B2B", "B2B-VPN",
    "DMZ", "DMZ-VPN",
    "Extranet", "Extranet-VPN",
    "Intranet", "Intranet-VPN",

    # Healthcare/specific verticals (from user list)
    "Aktion VPN", "BMC", "BMC-subs", "BWH-CP",
    "Dartmouth VPN", "Keene", "MAH", "MIT PM Trailer",
    "NSMC", "SGMSServer-VPN", "Sommerville", "UMH",

    # Common company patterns
    "CompanyVPN", "CorpVPN", "Corp-VPN",
    "MainOffice", "HeadOffice", "HQ", "HQ-VPN",
    "Branch", "BranchOffice", "Branch-VPN",
    "DataCenter", "DC-VPN",
    "Cloud", "CloudVPN", "AWS-VPN", "Azure-VPN",
    "Backup", "Backup-VPN", "DR", "DR-VPN",

    # Regional patterns
    "US", "US-VPN", "USA", "USA-VPN",
    "EU", "EU-VPN", "EMEA", "EMEA-VPN",
    "APAC", "APAC-VPN", "Asia", "Asia-VPN",
    "Americas", "Americas-VPN",
    "East", "West", "North", "South",
    "NYC", "LA", "CHI", "DAL", "ATL", "BOS", "SEA",
    "London", "Paris", "Tokyo", "Sydney",
]

# Flaws:
FLAW_DISC = "The IKE service could be discovered which should be restricted to only necessary parties"
FLAW_IKEV1 = "The following weak IKE version was supported: version 1"
FLAW_FING_VID = "The IKE service could be fingerprinted by analyzing the vendor ID (VID) which returned"
FLAW_FING_BACKOFF = "The IKE service could be fingerprinted by analyzing the responses received"
FLAW_ENC_DES = "The following weak encryption algorithm was supported: DES"
FLAW_ENC_IDEA = "The following weak encryption algorithm was supported: IDEA"
FLAW_ENC_BLOW = "The following weak encryption algorithm was supported: Blowfish"
FLAW_ENC_RC5 = "The following weak encryption algorithm was supported: RC5"
FLAW_ENC_CAST = "The following weak encryption algorithm was supported: CAST"
FLAW_ENC_3DES = "The following weak encryption algorithm was supported: 3DES"
FLAW_HASH_MD5 = "The following weak hash algorithm was supported: MD5"
FLAW_HASH_SHA1 = "The following weak hash algorithm was supported: SHA-1"
FLAW_DHG_1 = "The following weak key exchange group was supported: Diffie-Hellman group 1 (MODP-768)"
FLAW_DHG_2 = "The following weak key exchange group supported: Diffie-Hellman group 2 (MODP-1024)"
FLAW_DHG_5 = "The following weak key exchange group was supported: Diffie-Hellman group 5 (MODP-1536)"
FLAW_AUTH_PSK = "The following weak authentication method was supported: PSK"
FLAW_AUTH_DSA_SIG = "The following weak authentication method was supported: DSA signatures"
FLAW_AUTH_RSA_SIG = "The following moderate authentication method was supported: RSA signatures"
FLAW_AUTH_RSA_ENC = "The following weak authentication method was supported: RSA encryption"
FLAW_AUTH_RSA_ENC_REV = "The following moderate authentication method was supported: RSA revised encryption"
FLAW_AUTH_ELG_ENC = "The following weak authentication method was supported: ElGamel encryption"
FLAW_AUTH_ELG_ENC_REV = "The following weak authentication method was supported: ElGamel revised encryption"
FLAW_AUTH_ECDSA_SIG = "The following moderate authentication method was supported: ECDSA signature"
FLAW_AUTH_ECDSA_SHA256 = "The following moderate authentication method was supported: ECDSA SHA-256"
FLAW_AUTH_ECDSA_SHA384 = "The following moderate authentication method was supported: ECDSA SHA-384"
FLAW_AUTH_ECDSA_SHA512 = "The following moderate authentication method was supported: ECDSA SHA-512"
FLAW_AUTH_CRACK = "The following weak authentication method was supported: ISPRA CRACK"
FLAW_AUTH_HYB_RSA = "The following weak authentication method was supported: Hybrid RSA signatures"
FLAW_AUTH_HYB_DSA = "The following weak authentication method was supported: Hybrid DSA signatures"
FLAW_AGGR = "Aggressive Mode was accepted by the IKE service which should be disabled"
FLAW_AGGR_GRP_NO_ENC = "Aggressive Mode transmits group name without encryption"
FLAW_CID_ENUM = "Client IDs could be enumerated which should be restricted to only necessary parties or disabled"


###############################################################################
# Methods
###############################################################################

###############################################################################
def welcome():
	'''This method prints a welcome message.'''

	print('''
iker v. %s

The ike-scan based script that checks for security flaws in IPsec-based VPNs.

                               by Julio Gomez ( jgo@portcullis-security.com )
''' % VERSION)


###############################################################################
def checkPrivileges():
	'''This method checks if the script was launched with root privileges.
	@return True if it was launched with root privs and False in other case.'''

	return geteuid() == 0


###############################################################################
def validateTarget(target):
	'''Enhanced validation for IP addresses and domain names.
	@param target The IP address or domain name to validate
	@return True if valid, False otherwise'''
	
	target = target.strip()
	
	# Check if it's an IP address
	try:
		socket.inet_aton(target)
		return True
	except socket.error:
		pass
	
	# Check if it's a valid domain name
	try:
		socket.gethostbyname(target)
		return True
	except socket.gaierror:
		pass
	
	# Check CIDR notation
	if '/' in target:
		try:
			ip_part, cidr_part = target.split('/')
			socket.inet_aton(ip_part)
			cidr = int(cidr_part)
			return 0 <= cidr <= 32
		except (ValueError, socket.error):
			pass
	
	return False


###############################################################################
def calculateRiskScore(vpn_data):
	'''Calculate a risk score based on discovered vulnerabilities.
	@param vpn_data Dictionary containing VPN analysis results
	@return Risk score from 0-10'''
	
	score = 0
	
	if 'transforms' in vpn_data:
		for transform_data in vpn_data['transforms']:
			enc, hsh, auth, group = transform_data[0].split(', ')
			
			# Encryption scoring
			if enc in ['1']:  # DES
				score += 3
			elif enc in ['5']:  # 3DES
				score += 2
			elif enc.startswith('7/128'):  # AES-128
				score += 0.5
			
			# Hash scoring
			if hsh in ['1']:  # MD5
				score += 2
			elif hsh in ['2']:  # SHA1
				score += 1.5
			
			# Group scoring
			if group in ['1', '2']:  # MODP-768, MODP-1024
				score += 2
			elif group in ['5']:  # MODP-1536
				score += 1
	
	if 'aggressive' in vpn_data and vpn_data['aggressive']:
		score += 2  # Aggressive mode is a significant risk
	
	return min(score, 10)  # Cap at 10


###############################################################################
def generateJsonReport(vpns, scan_metadata):
	'''Generate a structured JSON report.
	@param vpns Dictionary containing all VPN scan results
	@param scan_metadata Dictionary containing scan configuration and timing
	@return JSON string'''
	
	report = {
		"scan_metadata": scan_metadata,
		"summary": {
			"total_targets": len(vpns),
			"vulnerable_targets": sum(1 for v in vpns.values() if calculateRiskScore(v) > 3),
			"scan_timestamp": strftime("%Y-%m-%d %H:%M:%S", localtime())
		},
		"results": {}
	}
	
	for ip, data in vpns.items():
		risk_score = calculateRiskScore(data)
		
		result = {
			"target": ip,
			"risk_score": risk_score,
			"risk_level": "Critical" if risk_score >= 7 else "High" if risk_score >= 5 else "Medium" if risk_score >= 3 else "Low",
			"vulnerabilities": [],
			"discovered_services": {}
		}
		
		if 'transforms' in data:
			result["discovered_services"]["main_mode"] = len(data['transforms'])
			for transform_data in data['transforms']:
				enc, hsh, auth, group = transform_data[0].split(', ')
				vuln = {
					"type": "weak_cryptography",
					"encryption": enc,
					"hash": hsh,
					"auth_method": auth,
					"dh_group": group,
					"transform": transform_data[1]
				}
				result["vulnerabilities"].append(vuln)
		
		if 'aggressive' in data and data['aggressive']:
			result["discovered_services"]["aggressive_mode"] = len(data['aggressive'])
			result["vulnerabilities"].append({
				"type": "aggressive_mode_enabled",
				"severity": "high",
				"description": "IKE Aggressive Mode is enabled and vulnerable to offline attacks"
			})
		
		if 'vid' in data:
			result["fingerprinting"] = {
				"vendor_ids": data['vid'],
				"fingerprint_confidence": "high" if len(data['vid']) > 2 else "medium"
			}
		
		report["results"][ip] = result
	
	return json.dumps(report, indent=2)


###############################################################################
def getArguments():
	'''This method parse the command line.
	@return the arguments received and a list of targets.'''
	global VERBOSE
	global FULLIKESCANPATH
	global ENCLIST
	global HASHLIST
	global AUTHLIST
	global GROUPLIST
	global XMLOUTPUT
	global CLIENTIDS
	global DELAY
	global HASHCAT_DIR

	targets = []

	parser = argparse.ArgumentParser()

	parser.add_argument("target", type=str, nargs='?', help="The IP address or the network (CIDR notation) to scan.")

	parser.add_argument("-v", "--verbose", action="store_true", help="Be verbose.")
	parser.add_argument("-d", "--delay", type=int, help="Delay between requests (in milliseconds). Default: 0 (No delay).")
	parser.add_argument("-i", "--input", type=str, help="An input file with an IP address/network per line.")
	parser.add_argument("-o", "--output", type=str, help="An output file to store the results.")
	parser.add_argument("-x", "--xml", type=str, help="An output file to store the results in XML format. Default: output.xml")
	parser.add_argument("-j", "--json", type=str, help="An output file to store the results in JSON format for API integration.")
	parser.add_argument("--encalgs", type=str, default="1 5 7", help="The encryption algorithms to check (1-7). Default: DES(1), 3DES(5), AES(7). Example: --encalgs=\"1 2 3 4 5 6 7/128 7/192 7/256 8\"")
	parser.add_argument("--hashalgs", type=str, default="1 2", help="The hash algorithms to check. Default: MD5(1) and SHA1(2). Example: --hashalgs=\"1 2 3 4 5 6\"")
	parser.add_argument("--authmethods", type=str, default="1 3 64221 65001", help="The authorization methods to check. Default: PSK(1), RSA Sig(3), Hybrid(64221), XAUTH(65001). Example: --authmethods=\"1 2 3 4 5 6 7 8 64221 65001\"")
	parser.add_argument("--kegroups", type=str, default="1 2 5 14", help="The key exchange groups to check. Default: MODP-768(1), MODP-1024(2), MODP-1536(5) and MODP-2048(14). Example: --kegroups=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18\"")
	parser.add_argument("--fullalgs", action="store_true", help="Equivalent to known sets of encalgs, hashalgs, authmethods and keygroups (NOTE: This may take a while!)")
	parser.add_argument("--quickscan", action="store_true", help="Perform a quick scan using only the most common weak algorithms (fast but less comprehensive)")
	parser.add_argument("--modernscan", action="store_true", help="Scan for modern secure algorithms instead of just weak ones")
	parser.add_argument("--ikepath", type=str, help="The FULL ike-scan path if it is not in the PATH variable and/or the name changed.")
	parser.add_argument("-c", "--clientids", type=str, help="A file (dictionary) with a client ID per line to enumerate valid client IDs in Aggressive Mode. Default: unset - uses built-in DEFAULT_GROUPS list.")
	parser.add_argument("-n", "--nofingerprint", action="store_true", help="Do not attempt to fingerprint targets.")
	parser.add_argument("--hashcat-dir", type=str, help="Directory to save hashcat-ready PSK hash files. Default: current directory.")
	parser.add_argument("--stop-on-first", action="store_true", help="Stop group enumeration after finding first valid group (faster)")
	parser.add_argument("--max-groups", type=int, default=0, help="Maximum number of groups to test (0 = unlimited)")

	args = parser.parse_args()

	if args.target:
		if validateTarget(args.target):
			targets.append(args.target.strip())
		else:
			print("\033[91m[*]\033[0m Invalid target specified: %s" % args.target)
			print("\033[91m[*]\033[0m Target must be a valid IP address, domain name, or CIDR notation.")
			exit(1)

	if args.input:
		try:
			f = open(args.input, "r")
			file_targets = f.readlines()
			f.close()
			
			for target in file_targets:
				target = target.strip()
				if target and not target.startswith('#'):  # Skip empty lines and comments
					if validateTarget(target):
						targets.append(target)
					else:
						print("\033[93m[*]\033[0m Skipping invalid target from file: %s" % target)
		except Exception as e:
			print("\033[91m[*]\033[0m The input file specified ('%s') could not be opened: %s" % (args.input, str(e)))

	if args.output:
		try:
			f = open(args.output, "w")
			f.close()
		except:
			print("\033[91m[*]\033[0m The output file specified ('%s') could not be opened/created." % args.output)

	if not targets:
		print("\033[91m[*]\033[0m You need to specify a target in CIDR notation or an input file (-i).")
		parser.parse_args(["-h"])
		exit(1)

	if args.verbose:
		VERBOSE = True

	if args.ikepath:
		FULLIKESCANPATH = args.ikepath

	if args.encalgs:
		ENCLIST = args.encalgs.split()
		for alg in ENCLIST:
			parts = alg.split('/')
			for p in parts:
				if not p.isdigit():
					print("\033[91m[*]\033[0m Wrong syntax for the encalgs parameter. Check syntax.")
					parser.parse_args(["-h"])
					exit(1)

	if args.hashalgs:
		HASHLIST = args.hashalgs.split()
		for alg in HASHLIST:
			if not alg.isdigit():
				print("\033[91m[*]\033[0m Wrong syntax for the hashalgs parameter. Check syntax.")
				parser.parse_args(["-h"])
				exit(1)

	if args.authmethods:
		AUTHLIST = args.authmethods.split()
		for alg in AUTHLIST:
			if not alg.isdigit():
				print("\033[91m[*]\033[0m Wrong syntax for the authmethods parameter. Check syntax.")
				parser.parse_args(["-h"])
				exit(1)

	if args.kegroups:
		GROUPLIST = args.kegroups.split()
		for alg in GROUPLIST:
			if not alg.isdigit():
				print("\033[91m[*]\033[0m Wrong syntax for the kegroups parameter. Check syntax.")
				parser.parse_args(["-h"])
				exit(1)

	if args.xml:
		XMLOUTPUT = args.xml
	try:
		f = open(XMLOUTPUT, "w")
		f.close()
	except:
		print("\033[91m[*]\033[0m The XML output file could not be opened/created.")

	if args.clientids:
		try:
			f = open(args.clientids, "r")
			f.close()
			CLIENTIDS = args.clientids
		except:
			print("\033[91m[*]\033[0m The client ID dictionary could not be read. This test won't be launched.")

	if args.delay:
		DELAY = args.delay

	if args.hashcat_dir:
		HASHCAT_DIR = args.hashcat_dir
		try:
			import os
			os.makedirs(HASHCAT_DIR, exist_ok=True)
			print("\033[92m[*]\033[0m Hashcat output directory: %s" % HASHCAT_DIR)
		except Exception as e:
			print("\033[91m[*]\033[0m Could not create hashcat output directory: %s" % str(e))

	if args.fullalgs:
		ENCLIST = FULLENCLIST
		HASHLIST = FULLHASHLIST
		AUTHLIST = FULLAUTHLIST
		GROUPLIST = FULLGROUPLIST
	elif args.quickscan:
		# Quick scan focuses on most common weak algorithms
		ENCLIST = ['1', '5']  # DES, 3DES
		HASHLIST = ['1', '2']  # MD5, SHA1
		AUTHLIST = ['1']  # PSK
		GROUPLIST = ['1', '2']  # MODP-768, MODP-1024
		print("\033[92m[*]\033[0m Quick scan mode enabled - testing most common weak algorithms")
	elif args.modernscan:
		# Modern scan focuses on current secure algorithms
		ENCLIST = MODERN_SECURE_ENCS
		HASHLIST = MODERN_SECURE_HASHES
		AUTHLIST = ['3', '9', '10', '11']  # RSA, ECDSA variants
		GROUPLIST = MODERN_SECURE_GROUPS
		print("\033[92m[*]\033[0m Modern scan mode enabled - testing current secure algorithms")

	return args, targets


###############################################################################
def printMessage(message, path=None):
	'''This method prints a message in the standard output and in the output file
	if it existed.
	@param message The message to be printed.
	@param path The output file, if specified.'''

	print(message)

	if path:
		try:
			f = open(path, "a")
			f.write("%s\n" % message)
			f.close()
		except:
			pass


###############################################################################
def launchProcess(command):
	'''Launch a command in a different process and return the process.'''

	process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

	error = process.stderr.readlines()
	error = str(error).strip('[]')
	if len(error) > 0 and "ERROR" in error[0] and "port 500" in error[0]:
		printMessage("\033[91m[*]\033[0m Something was wrong! There may be another instance of ike-scan running. Ensure that there is no other proccess using ike-scan before to launch iker.")
		exit(1)

	return process


###############################################################################
def delay(time):
	'''This method wait for a delay.
	@param time The time to wait in milliseconds.'''

	if time:
		sleep(time / 1000.0)


###############################################################################
def waitForExit(args, vpns, ip, key, value):
	'''This method shows a progressbar during the discovery of transforms.
	@param top The total number of transforms combinations
	@param current The iteration within the bucle (which transform is checking).
	@param transform The string that represents the transform.'''

	try:
		printMessage("\033[91m[*]\033[0m You pressed Ctrl+C. Do it again to exit or wait to continue but skipping this step.")
		vpns[ip][key] = value
		sleep(2)
		if key not in list(vpns[ip].keys()) or not vpns[ip][key]:
			printMessage("[*] Skipping test...", args.output)
	except KeyboardInterrupt:
		parseResults(args, vpns)
		printMessage("iker finished at %s" % strftime("%a, %d %b %Y %H:%M:%S +0000", localtime()), args.output)
		exit(0)


###############################################################################
def updateProgressBar(top, current, transform):
	'''This method shows a progressbar during the discovery of transforms.
	@param top The total number of transforms combinations
	@param current The iteration within the bucle (which transform is checking).
	@param transform The string that represent the transform.'''

	progressbar = "[....................] %d%% - Current transform: %s\r"
	tt = 20
	step = top / tt
	# Progress: [====================] 10% : DES-MD5
	cc = current / step
	cc = int(cc)
	progressbar = progressbar.replace(".", "=", cc)
	perctg = current * 100 / top
	stdout.write(progressbar % (perctg, transform))
	stdout.flush()


###############################################################################
def checkIkeScan():
	'''This method checks for the ike-scan location.
	@return True if ike-scan was found and False in other case.'''

	proccess = subprocess.Popen("%s --version" % FULLIKESCANPATH, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proccess.wait()

	output = proccess.stderr.read()
	output = str(output)

	if "ike-scan" in output.lower():
		return True
	else:
		return False


###############################################################################
def discovery(args, targets, vpns):
	'''Run ike-scan to discover IKE services and update the vpns variable with the information found.
	@param args The command line parameters
	@param targets The targets specified (IPs and/or networks)
	@param vpns A dictionary to store all the information'''

	printMessage("[*] Discovering IKE services, please wait...", args.output)

	# Launch ike-scan for each target and parse the output
	for target in targets:

		process = launchProcess("%s -M %s" % (FULLIKESCANPATH, target))
		process.wait()

		ip = None
		info = ""

		for line in io.TextIOWrapper(process.stdout, encoding="utf-8"):
			if not line.split() or 'Starting ike-scan' in line or 'Ending ike-scan' in line:
				continue

			if line[0].isdigit():

				if info:
					vpns[ip] = {}
					vpns[ip]["handshake"] = info.strip()
					vpns[ip]["v1"] = True

					if VERBOSE:
						printMessage(info, args.output)
					else:
						printMessage("\033[92m[*]\033[0m IKE version 1 is supported by %s" % ip, args.output)

				ip = line.split()[0]
				info = line
			else:
				info = info + line

		if info and ip not in list(vpns.keys()):
			vpns[ip] = {}
			vpns[ip]["handshake"] = info.strip()
			vpns[ip]["v1"] = True
			if VERBOSE:
				printMessage(info, args.output)
			else:
				printMessage("\033[92m[*]\033[0m IKE version 1 is supported by %s" % ip, args.output)


###############################################################################
def checkIKEv2(args, targets, vpns):
	'''This method checks if IKE version 2 is supported.
	@param args The command line parameters
	@param vpns A dictionary to store all the information'''

	printMessage("[*] Checking for IKE version 2 support...", args.output)

	try:
		# Check the IKE v2 support for each target
		for target in targets:

			process = launchProcess("%s -2 -M %s" % (FULLIKESCANPATH, target))
			process.wait()

			v2_supported = False
			ip = target

			for line in io.TextIOWrapper(process.stdout, encoding="utf-8"):
				if not line.split() or "Starting ike-scan" in line or "Ending ike-scan" in line:
					continue

				# Get IP from response line
				if line[0].isdigit():
					ip = line.split()[0]

				# Check for IKEv2 SA response (indicates IKEv2 is supported)
				if "SA=" in line:
					v2_supported = True

			# Report result
			if v2_supported:
				printMessage("\033[92m[*]\033[0m IKE version 2 is supported by %s" % ip, args.output)
				if ip in list(vpns.keys()):
					vpns[ip]["v2"] = True
				else:
					printMessage("[*] IKE version 1 support was not identified in this host (%s). iker will not perform more tests against this host." % ip, args.output)
			else:
				printMessage("\033[91m[*]\033[0m IKE version 2 is NOT supported by %s" % ip, args.output)
				if ip in list(vpns.keys()):
					vpns[ip]["v2"] = False

		# Mark any remaining IPs as not supporting v2
		for ip in list(vpns.keys()):
			if "v2" not in list(vpns[ip].keys()):
				vpns[ip]["v2"] = False

	except KeyboardInterrupt:
		waitForExit(args, vpns, ip, "v2", False)


###############################################################################
def fingerprintVID(args, vpns, handshake=None):
	'''This method tries to discover the vendor of the devices by checking
	the VID. Results are written in the vpns variable.
	@param args The command line parameters
	@param vpns A dictionary to store all the information
	@param handshake The handshake where look for a VID'''

	for ip in list(vpns.keys()):

		if "vid" not in list(vpns[ip].keys()):
			vpns[ip]["vid"] = []

		# Fingerprint based on VIDs
		hshk = vpns[ip]["handshake"]
		if handshake:
			if ip in handshake:
				hshk = handshake
			else:
				continue

		transform = ""
		vid = ""
		for line in hshk.splitlines():

			if "SA=" in line:
				transform = line.strip()[4:-1]

			if "VID=" in line and "(" in line and ")" in line and "draft-ietf" not in line and "IKE Fragmentation" not in line and "Dead Peer Detection" not in line and "XAUTH" not in line and "RFC 3947" not in line and "heartbeat_notify" not in line.lower():

				vid = line[line.index('(')+1:line.index(')')]

		enc = False
		for pair in vpns[ip]["vid"]:
			if pair[0] == vid:
				enc = True

		if vid and not enc:
			vpns[ip]["vid"].append((vid, hshk))

			printMessage("\033[92m[*]\033[0m Vendor ID identified for IP %s with transform %s: %s" % (ip, transform, vid), args.output)


###############################################################################
def fingerprintShowbackoff(args, vpns, transform="", vpnip=""):
	'''This method tries to discover the vendor of the devices and the results
	are written in the vpns variable.
	@param args The command line parameters
	@param vpns A dictionary to store all the information'''

	printMessage("\n[*] Trying to fingerprint the devices%s. This proccess is going to take a while (1-5 minutes per IP). Be patient..." % (transform and " (again)" or transform), args.output)

	try:
		for ip in list(vpns.keys()):

			if vpnip and vpnip != ip:
				continue

			transform = transform.replace(" ", "")
			process = launchProcess("%s --showbackoff %s %s" % (FULLIKESCANPATH, ((transform and ("--trans="+transform) or transform)), ip))
			vpns[ip]["showbackoff"] = ""
			process.wait()

			# Fingerprint based on the VPN service behavior
			for line in io.TextIOWrapper(process.stdout, encoding="utf-8"):
				line = str(line)
				if "Implementation guess:" in line:

					vendor = line[line.index('Implementation guess:')+22:].strip()

					if vendor.lower() != "unknown":

						vpns[ip]["showbackoff"] = vendor

						printMessage("\033[92m[*]\033[0m Implementation guessed for IP %s: %s" % (ip, vendor), args.output)

			if not vpns[ip]["showbackoff"]:
				if transform:
					printMessage("\033[91m[*]\033[0m The device %s could not be fingerprinted. It won't be retry again." % ip, args.output)
					vpns[ip]["showbackoff"] = " "
				else:
					printMessage("\033[91m[*]\033[0m The device %s could not be fingerprinted because no transform is known." % ip, args.output)
	except KeyboardInterrupt:
		waitForExit(args, vpns, ip, "showbackoff", " ")


###############################################################################
def checkEncryptionAlgs(args, vpns):
	'''This method tries to discover accepted transforms. The results
	are written in the vpns variable.
	@param args The command line parameters
	@param vpns A dictionary to store all the information'''

	try:
		top = len(ENCLIST) * len(HASHLIST) * len(AUTHLIST) * len(GROUPLIST)
		# current = 0
		for ip in list(vpns.keys()):

			current = 0
			printMessage("\n[*] Looking for accepted transforms at %s" % ip, args.output)
			vpns[ip]["transforms"] = []

			for enc in ENCLIST:
				for hsh in HASHLIST:
					for auth in AUTHLIST:
						for group in GROUPLIST:

							process = launchProcess("%s -M --trans=%s,%s,%s,%s %s" % (FULLIKESCANPATH, enc, hsh, auth, group, ip))
							process.wait()

							output = io.TextIOWrapper(process.stdout, encoding="utf-8")
							info = ""
							new = False
							for line in output:
								if "Starting ike-scan" in line or "Ending ike-scan" in line or line.strip() == "":
									continue

								line = line.strip()
								info += line + "\n"

								if "SA=" in line:
									new = True
									transform = line[4:-1]
									printMessage("\033[92m[*]\033[0m Transform found: %s" % transform, args.output)

							if new:
								vpns[ip]["transforms"].append(("%s, %s, %s, %s" % (enc, hsh, auth, group), transform, info))
								fingerprintVID(args, vpns, info)
								# If the backoff could not be fingerprinted before...
								if not args.nofingerprint and not vpns[ip]["showbackoff"]:
									fingerprintShowbackoff(args, vpns, vpns[ip]["transforms"][0][0], ip)

							current += 1
							updateProgressBar(top, current, str(enc)+","+str(hsh)+","+str(auth)+","+str(group))
							delay(DELAY)
	except KeyboardInterrupt:
		if "transforms" not in list(vpns[ip].keys()) or not vpns[ip]["transforms"]:
			waitForExit(args, vpns, ip, "transforms", [])
		else:
			waitForExit(args, vpns, ip, "transforms", vpns[ip]["transforms"])


###############################################################################
def checkAggressive(args, vpns):
	'''This method tries to check if aggressive mode is available. If so,
	it also store the returned handshake to a text file.
	Tries with common group IDs from DEFAULT_GROUPS for devices like SonicWall
	that require a valid group ID for aggressive mode.
	@param args The command line parameters
	@param vpns A dictionary to store all the information'''

	from datetime import datetime

	# Quick group IDs to test for aggressive mode detection
	quick_groups = ["GroupVPN", "vpn", "VPN", "default", "ipsec", "test"]

	try:
		top = len(ENCLIST) * len(HASHLIST) * len(AUTHLIST) * len(GROUPLIST)
		current = 0
		for ip in list(vpns.keys()):

			printMessage("\n[*] Looking for accepted transforms in aggressive mode at %s" % ip, args.output)
			vpns[ip]["aggressive"] = []

			for enc in ENCLIST:
				for hsh in HASHLIST:
					for auth in AUTHLIST:
						for group in GROUPLIST:

							# Determine hash output path
							timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
							if HASHCAT_DIR:
								hash_path = os.path.join(HASHCAT_DIR, "%s_aggressive_%s_%s_%s_%s_%s" % (ip, enc, hsh, auth, group, timestamp))
							else:
								hash_path = "%s_handshake_%s" % (ip, timestamp)

							# First try without group ID
							process = launchProcess("%s -M --aggressive -P%s --trans=%s,%s,%s,%s %s" % (FULLIKESCANPATH, hash_path, enc, hsh, auth, group, ip))
							process.wait()

							output = io.TextIOWrapper(process.stdout, encoding="utf-8")

							info = ""
							new = False
							for line in output:
								if "Starting ike-scan" in line or "Ending ike-scan" in line or line.strip() == "":
									continue

								info += line + "\n"

								if "SA=" in line:
									new = True
									transform = line.strip()[4:-1]
									printMessage("\033[92m[*]\033[0m Aggressive mode supported with transform: %s" % transform, args.output)

							# If no response, try with common group IDs (SonicWall needs this)
							if not new:
								for gid in quick_groups:
									process = launchProcess("%s -M --aggressive -P%s --trans=%s,%s,%s,%s --id=\"%s\" %s" % (FULLIKESCANPATH, hash_path, enc, hsh, auth, group, gid, ip))
									process.wait()

									output = io.TextIOWrapper(process.stdout, encoding="utf-8")

									info = ""
									for line in output:
										if "Starting ike-scan" in line or "Ending ike-scan" in line or line.strip() == "":
											continue

										info += line + "\n"

										if "SA=" in line:
											new = True
											transform = line.strip()[4:-1]
											printMessage("\033[92m[*]\033[0m Aggressive mode supported with transform: %s (group: %s)" % (transform, gid), args.output)
											break

									if new:
										break

									delay(DELAY)

							if new:
								vpns[ip]["aggressive"].append(("%s, %s, %s, %s" % (enc, hsh, auth, group), transform, info))
								fingerprintVID(args, vpns, info)
								# If the backoff could not be fingerprinted before...
								if not args.nofingerprint and not vpns[ip]["showbackoff"]:
									fingerprintShowbackoff(args, vpns, vpns[ip]["aggressive"][0][0], ip)

								# Create hashcat-ready file if hash was captured
								if os.path.exists(hash_path):
									hashcat_path = hash_path + ".hashcat"
									try:
										with open(hash_path, 'r') as f:
											hash_data = f.read()
										with open(hashcat_path, 'w') as f:
											f.write(hash_data)
										printMessage("    \033[92m[+]\033[0m Hashcat file saved: %s (mode 5400)" % hashcat_path, args.output)
									except:
										pass

							current += 1
							updateProgressBar(top, current, str(enc)+","+str(hsh)+","+str(auth)+","+str(group))
							delay(DELAY)
	except KeyboardInterrupt:
		if "aggressive" not in list(vpns[ip].keys()) or not vpns[ip]["aggressive"]:
			waitForExit(args, vpns, ip, "aggressive", [])
		else:
			waitForExit(args, vpns, ip, "aggressive", vpns[ip]["aggressive"])


###############################################################################
# Common VPN passwords for quick crack attempts
COMMON_VPN_PASSWORDS = [
	"vpn", "VPN", "vpn123", "VPN123", "vpn@123", "VPN@123",
	"password", "Password", "password1", "Password1", "password123",
	"admin", "Admin", "admin123", "Admin123",
	"cisco", "Cisco", "cisco123", "Cisco123",
	"sonicwall", "SonicWall", "sonicwall123",
	"firewall", "Firewall", "firewall123",
	"remote", "Remote", "remote123",
	"access", "Access", "access123",
	"secret", "Secret", "secret123",
	"letmein", "welcome", "Welcome",
	"changeme", "Changeme", "changeme123",
	"test", "Test", "test123", "Test123",
	"guest", "Guest", "guest123",
	"default", "Default", "default123",
	"123456", "1234567", "12345678", "123456789",
	"qwerty", "Qwerty123",
	"company", "Company123",
	"ipsec", "IPSec", "ipsec123",
	"tunnel", "Tunnel", "tunnel123",
	"connect", "Connect", "connect123",
	"secure", "Secure", "secure123",
	"private", "Private", "private123",
]


###############################################################################
def enumerateAuthMethods(args, vpns):
	'''This method tests different authentication methods in Phase 1 IKE negotiation.

	IMPORTANT NOTE ON MFA DETECTION:
	There are two ways MFA can be implemented in IKE VPNs:

	1. XAUTH-PSK (Auth Method 65001) - XAUTH negotiated IN Phase 1
	   - Detectable via ike-scan --trans parameter
	   - Server announces XAUTH support during SA negotiation

	2. Mode Config XAUTH - XAUTH requested AFTER Phase 1 completes
	   - NOT detectable without completing Phase 1 and attempting Phase 2
	   - Server sends TRANSACTION request after IKE SA established
	   - Common on SonicWall, Cisco, and other enterprise firewalls

	This function tests for Type 1 only. A server may still require XAUTH/MFA
	via Mode Config even if this test shows "No MFA detected".

	@param args The command line parameters
	@param vpns A dictionary to store all the information'''

	# Auth method IDs: 1=PSK, 3=RSA Sig, 5=RSA Enc, 64221=Hybrid, 65001=XAUTH
	auth_methods = [
		(1, "PSK (Pre-Shared Key)", False),
		(65001, "XAUTH-PSK (Phase 1)", True),  # MFA in Phase 1
		(3, "RSA Signatures", False),
		(64221, "Hybrid RSA", True),  # MFA capable
		(65005, "XAUTH RSA", True),  # MFA capable
	]

	for ip in list(vpns.keys()):
		if "transforms" not in vpns[ip] or not vpns[ip]["transforms"]:
			continue

		printMessage("\n[*] Testing Phase 1 authentication methods for %s..." % ip, args.output)
		vpns[ip]["auth_methods"] = []
		vpns[ip]["phase1_mfa"] = False  # Renamed for clarity

		# Get a working transform to use as base
		base_trans = vpns[ip]["transforms"][0][0]
		parts = base_trans.split(", ")
		if len(parts) >= 4:
			enc, hsh, _, grp = parts[0], parts[1], parts[2], parts[3]
		else:
			continue

		for auth_id, auth_name, mfa_capable in auth_methods:
			process = launchProcess("%s -M --trans=%s,%s,%s,%s %s" % (
				FULLIKESCANPATH, enc, hsh, auth_id, grp, ip))
			process.wait()

			accepted = False
			for line in io.TextIOWrapper(process.stdout, encoding="utf-8"):
				if "SA=" in line:
					accepted = True
					break

			if accepted:
				vpns[ip]["auth_methods"].append((auth_id, auth_name, mfa_capable))
				if mfa_capable:
					vpns[ip]["phase1_mfa"] = True
					printMessage("    \033[92m[+]\033[0m %s: Accepted (MFA in Phase 1)" % auth_name, args.output)
				else:
					printMessage("    \033[93m[+]\033[0m %s: Accepted" % auth_name, args.output)
			else:
				printMessage("    \033[91m[-]\033[0m %s: Rejected" % auth_name, args.output)

			delay(DELAY)

		# Print MFA summary with important caveat
		if not vpns[ip]["phase1_mfa"]:
			printMessage("    \033[93m[!]\033[0m Phase 1 MFA (XAUTH-PSK) not negotiated", args.output)
			printMessage("    \033[93m[*]\033[0m Note: Server may still require Mode Config XAUTH after PSK auth", args.output)
			printMessage("    \033[93m[*]\033[0m Full MFA detection requires attempting actual VPN connection", args.output)
		else:
			printMessage("    \033[92m[+]\033[0m MFA-capable authentication negotiated in Phase 1", args.output)


###############################################################################
def extractVPNIdentity(hash_data):
	'''Extract VPN Identity from PSK hash data.
	@param hash_data The raw hash data from ike-scan
	@return The VPN identity string or None'''

	# Hash format: ...:VPN_ID_HEX:hash1:hash2:hash3
	# VPN ID is typically in position 5 (0-indexed) as hex
	try:
		parts = hash_data.strip().split(':')
		if len(parts) >= 6:
			# VPN ID is hex encoded, format like "020000005742494657"
			# First bytes are type/length, rest is the ID
			vpn_id_hex = parts[5]
			if vpn_id_hex.startswith("0"):
				# Skip first 4 bytes (8 hex chars) which are type/length
				id_hex = vpn_id_hex[8:]
				# Convert hex to ASCII
				vpn_id = bytes.fromhex(id_hex).decode('ascii', errors='ignore').strip('\x00')
				if vpn_id and vpn_id.isprintable():
					return vpn_id
	except:
		pass
	return None


###############################################################################
def quickCrack(args, vpns):
	'''Attempt to crack captured PSK hashes with common passwords.
	@param args The command line parameters
	@param vpns A dictionary to store all the information'''

	# Check if psk-crack is available
	try:
		proc = subprocess.Popen("which psk-crack", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		proc.wait()
		if proc.returncode != 0:
			printMessage("\n[*] psk-crack not found, skipping quick crack attempt", args.output)
			return
	except:
		return

	for ip in list(vpns.keys()):
		if "psk_hashes" not in vpns[ip] or not vpns[ip]["psk_hashes"]:
			continue

		printMessage("\n[*] Attempting quick password crack for %s..." % ip, args.output)
		printMessage("    Testing %d common VPN passwords..." % len(COMMON_VPN_PASSWORDS), args.output)

		for hash_info in vpns[ip]["psk_hashes"]:
			hash_file = hash_info.get("hash_file", "")
			group = hash_info.get("group", "unknown")

			if not hash_file or not os.path.exists(hash_file):
				continue

			# Create temp wordlist
			temp_wordlist = "/tmp/iker_quick_wordlist.txt"
			with open(temp_wordlist, 'w') as f:
				f.write('\n'.join(COMMON_VPN_PASSWORDS))

			# Try psk-crack
			process = launchProcess("psk-crack -d %s %s 2>/dev/null" % (temp_wordlist, hash_file))
			process.wait()

			output = process.stdout.read().decode('utf-8', errors='ignore')

			if 'key "' in output.lower() or 'found:' in output.lower():
				# Extract the password
				for line in output.split('\n'):
					if 'key "' in line.lower() or 'found' in line.lower():
						printMessage("    \033[92m[+]\033[0m PASSWORD CRACKED for group '%s'!" % group, args.output)
						printMessage("    \033[92m[+]\033[0m %s" % line.strip(), args.output)
						vpns[ip]["cracked_psk"] = line.strip()
						break
			else:
				printMessage("    [-] No match found for group '%s' with common passwords" % group, args.output)

			# Clean up
			try:
				os.remove(temp_wordlist)
			except:
				pass


###############################################################################
def enumerateGroupIDCiscoDPD(args, vpns, ip):
	'''This method tries to enumerate valid client IDs from a dictionary.
	@param args The command line parameters
	@param vpns A dictionary to store all the information
	@param ip The ip where perform the enumeration'''

	# Check if possible

	process = launchProcess("%s --aggressive --trans=%s --id=badgroupiker573629 %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], ip))
	process.wait()

	possible = True
	for line in io.TextIOWrapper(process.stdout, encoding="utf-8"):
		line = str(line)
		if "dead peer" in line.lower():
			possible = False
			break

	if possible:
		delay(DELAY)

		# Enumerate users
		try:
			fdict = open(args.clientids, "r")
			cnt = 0

			for cid in fdict:
				cid = cid.strip()

				process = launchProcess("%s --aggressive --trans=%s --id=%s %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], cid, ip))
				process.wait()

				output_lines = list(io.TextIOWrapper(process.stdout, encoding="utf-8"))
				output = output_lines[1].strip() if len(output_lines) > 1 else ""

				# Check if the service is still responding
				msg = re.sub(r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', output) if output else ""
				if not msg:
					cnt += 1
					if cnt > 3:
						printMessage("\033[91m[*]\033[0m The IKE service cannot be reached; a firewall might filter your IP address. DPD Group ID enumeration could not be performed...", args.output)
						return False

				enc = False
				for line in output_lines:
					line = str(line)
					if "dead peer" in line.lower():
						enc = True
						break

				delay(DELAY)

				# Re-check the same CID if it looked valid
				if enc:
					process = launchProcess("%s --aggressive --trans=%s --id=%s %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], cid, ip))
					process.wait()

					enc = False
					for line in io.TextIOWrapper(process.stdout, encoding="utf-8"):
						line = str(line)
						if "dead peer" in line.lower():
							vpns[ip]["clientids"].append(cid)
							printMessage("\033[92m[*]\033[0m A potential valid client ID was found: %s" % cid, args.output)
							break

					delay(DELAY)

			fdict.close()
		except:
			possible = False

	return possible


###############################################################################
def enumerateGroupID(args, vpns):
	'''This method tries to enumerate valid client IDs from a dictionary.
	If no dictionary is provided, uses DEFAULT_GROUPS.
	For valid groups, captures PSK hash in hashcat format.
	@param args The command line parameters
	@param vpns A dictionary to store all the information'''

	from datetime import datetime

	# Get group list - use file if provided, otherwise DEFAULT_GROUPS
	group_list = []
	if args.clientids:
		try:
			fdict = open(args.clientids, "r")
			group_list = [line.strip() for line in fdict if line.strip()]
			fdict.close()
			printMessage("\033[92m[*]\033[0m Loaded %d group names from %s" % (len(group_list), args.clientids), args.output)
		except:
			printMessage("\033[91m[*]\033[0m Could not read client ID file, using default groups", args.output)
			group_list = DEFAULT_GROUPS
	else:
		group_list = DEFAULT_GROUPS
		printMessage("\033[92m[*]\033[0m Using %d built-in default group names" % len(group_list), args.output)

	for ip in list(vpns.keys()):

		vpns[ip]["clientids"] = []
		vpns[ip]["psk_hashes"] = []  # Store captured PSK hashes

		if not len(vpns[ip]["aggressive"]):
			continue

		printMessage("\n[*] Trying to enumerate valid client IDs for IP %s" % ip, args.output)

		# Check if the device is vulnerable to Cisco DPD group ID enumeration and exploit it
		done = False
		if "showbackoff" in list(vpns[ip].keys()) and "cisco" in vpns[ip]["showbackoff"].lower():
			done = enumerateGroupIDCiscoDPD(args, vpns, ip)

		if "vid" in list(vpns[ip].keys()) and len(vpns[ip]["vid"]) > 0:
			for vid in vpns[ip]["vid"]:
				if "cisco" in vid[0].lower():
					done = enumerateGroupIDCiscoDPD(args, vpns, ip)
					break

		if done:
			continue  # If Cisco DPD enumeration, continue

		#  Try to guess the "unvalid client ID" message
		def get_response_line(proc):
			"""Get the second line (index 1) from process output"""
			lines = list(io.TextIOWrapper(proc.stdout, encoding="utf-8"))
			if len(lines) > 1:
				return lines[1].strip()
			return ""

		process = launchProcess("%s --aggressive --trans=%s --id=badgroupiker123456 %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], ip))
		process.wait()
		raw_msg = get_response_line(process)
		message1 = re.sub(r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', raw_msg) if raw_msg else ""

		delay(DELAY)

		process = launchProcess("%s --aggressive --trans=%s --id=badgroupiker654321 %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], ip))
		process.wait()
		raw_msg = get_response_line(process)
		message2 = re.sub(r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', raw_msg) if raw_msg else ""

		delay(DELAY)

		process = launchProcess("%s --aggressive --trans=%s --id=badgroupiker935831 %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], ip))
		process.wait()
		raw_msg = get_response_line(process)
		message3 = re.sub(r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', raw_msg) if raw_msg else ""

		delay(DELAY)

		invalidmsg = ""
		if message1 == message2:
			invalidmsg = message1
			if message1 != message3:
				vpns[ip]["clientids"].append("badgroupiker935831")
		elif message1 == message3:
			invalidmsg = message1
			vpns[ip]["clientids"].append("badgroupiker654321")
		elif message2 == message3:
			invalidmsg = message2
			vpns[ip]["clientids"].append("badgroupiker123456")
		else:
			printMessage("\033[91m[*]\033[0m It was not possible to get a common response to invalid client IDs. This test will be skipped.", args.output)
			return

		# Enumerate groups
		cnt = 0
		total = len(group_list)
		found_count = 0

		for idx, cid in enumerate(group_list):
			cid = cid.strip()
			if not cid:
				continue

			# Check max-groups limit
			if args.max_groups > 0 and idx >= args.max_groups:
				printMessage("\n[*] Reached max-groups limit (%d), stopping enumeration" % args.max_groups, args.output)
				break

			# Progress indicator - always show so user knows it's working
			stdout.write("\r[*] Testing group %d/%d: %-30s" % (idx + 1, total, cid[:30]))
			stdout.flush()

			process = launchProcess("%s --aggressive --trans=%s --id=%s %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], cid, ip))
			process.wait()
			raw_msg = get_response_line(process)
			msg = re.sub(r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', raw_msg) if raw_msg else ""

			if not msg:
				cnt += 1
				if cnt > 3:
					printMessage("\n\033[91m[*]\033[0m The IKE service cannot be reached; a firewall might filter your IP address. Skipping to the following service...", args.output)
					break

			elif msg != invalidmsg:
				vpns[ip]["clientids"].append(cid)
				printMessage("\n\033[92m[+]\033[0m VALID GROUP FOUND: %s" % cid, args.output)

				# Capture PSK hash for this valid group
				timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
				safe_cid = cid.replace(" ", "_").replace("/", "_")

				# Determine output path
				if HASHCAT_DIR:
					hash_path = os.path.join(HASHCAT_DIR, "psk_%s_%s_%s" % (ip, safe_cid, timestamp))
				else:
					hash_path = "psk_%s_%s_%s" % (ip, safe_cid, timestamp)

				# Capture hash with -P flag
				printMessage("    [*] Capturing PSK hash...", args.output)
				hash_process = launchProcess("%s -A -M --id=\"%s\" -P%s %s" % (FULLIKESCANPATH, cid, hash_path, ip))
				hash_process.wait()

				if os.path.exists(hash_path):
					# Read and display hash info
					try:
						with open(hash_path, 'r') as f:
							hash_data = f.read().strip()

						if hash_data:
							# Extract the final hash (last colon-separated field)
							parts = hash_data.split(':')
							final_hash = ""
							if len(parts) >= 9:
								final_hash = parts[-1]
								printMessage("    \033[92m[+]\033[0m PSK Hash: %s" % final_hash, args.output)

							# Extract VPN Identity
							vpn_id = extractVPNIdentity(hash_data)
							if vpn_id:
								printMessage("    \033[92m[+]\033[0m VPN Identity: %s" % vpn_id, args.output)
								if "vpn_identity" not in vpns[ip]:
									vpns[ip]["vpn_identity"] = vpn_id

							# Create hashcat-ready file
							hashcat_path = hash_path + ".hashcat"
							with open(hashcat_path, 'w') as f:
								f.write(hash_data)

							printMessage("    \033[92m[+]\033[0m Hash saved: %s" % hash_path, args.output)
							printMessage("    \033[92m[+]\033[0m Hashcat file: %s (mode 5400)" % hashcat_path, args.output)

							vpns[ip]["psk_hashes"].append({
								"group": cid,
								"hash_file": hash_path,
								"hashcat_file": hashcat_path,
								"hash": final_hash if len(parts) >= 9 else hash_data,
								"vpn_identity": vpn_id
							})
					except Exception as e:
						printMessage("    \033[91m[*]\033[0m Error reading hash file: %s" % str(e), args.output)
				else:
					printMessage("    \033[91m[*]\033[0m Failed to capture PSK hash for group: %s" % cid, args.output)

				# Check if we should stop after first valid group
				if args.stop_on_first or args.quickscan:
					printMessage("\n[*] Found valid group, stopping enumeration (--stop-on-first)", args.output)
					break

			delay(DELAY)

		if VERBOSE:
			stdout.write("\n")
			stdout.flush()

		# Print summary for this IP
		if vpns[ip]["psk_hashes"]:
			printMessage("\n\033[92m[+]\033[0m Captured %d PSK hash(es) for %s" % (len(vpns[ip]["psk_hashes"]), ip), args.output)
			printMessage("    To crack with hashcat: hashcat -m 5400 <hash_file> <wordlist>", args.output)


###############################################################################
def parseResults(args, vpns, startTime, endTime):
	'''This method analyzes the results and prints them where correspond.
	@param args The command line parameters
	@param vpns A dictionary to store all the information
	@param startTime A timestamp of when the script began
	@param endTime A timestamp of when the script finished'''


	ENC_ANNOUNCEMENT = False
	HASH_ANNOUNCEMENT = False
	KE_ANNOUNCEMENT = False
	AUTH_ANNOUNCEMENT = False
	ENC_ANNOUNCEMENT_TEXT = "Weak encryption algorithms are those considered broken by industry standards or key length is less than 128 bits."
	HASH_ANNOUNCEMENT_TEXT = "Weak hash algorithms are those considered broken by industry standards."
	KE_ANNOUNCEMENT_TEXT = "Weak key exchange groups are those considered broken by industry standards or modulus is less than 2048 bits."
	AUTH_ANNOUNCEMENT_TEXT = "Weak authentication methods are those not using multifactor authentication or not requiring mutual authentication."

	printMessage("\n\nResults:\n--------", args.output)

	pathxml = XMLOUTPUT

	try:
		fxml = open(pathxml, "a")
		fxml.write("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n")
		fxml.write("<?time start=\"%s\" end=\"%s\" ?>\n" % (startTime, endTime))
		fxml.write("<best_practices>\n")
		fxml.write("\t<encryption algorithms=\"%s\"></encryption>\n" % ENC_ANNOUNCEMENT_TEXT)
		fxml.write("\t<hash algorithms=\"%s\"></hash>\n" % HASH_ANNOUNCEMENT_TEXT)
		fxml.write("\t<key_exchange groups=\"%s\"></key_exchange>\n" % KE_ANNOUNCEMENT_TEXT)
		fxml.write("\t<authentication methods=\"%s\"></authentication>\n" % AUTH_ANNOUNCEMENT_TEXT)
		fxml.write("</best_practices>\n")
		fxml.write("<services>\n")
	except:
		pass

	for ip in list(vpns.keys()):

		try:
			fxml.write("\t<service ip=\"%s\">\n\t\t<flaws>\n" % ip)
		except:
			pass

		# Discoverable
		printMessage("\nResults for IP %s:\n" % ip, args.output)
		printMessage("\033[91m[*]\033[0m %s" % FLAW_DISC, args.output)
		flawid = 0
		try:
			fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_DISC, vpns[ip]["handshake"]))
			flawid += 1
		except:
			pass

		# IKE v1
		if "v1" in list(vpns[ip].keys()) and vpns[ip]["v1"]:
			printMessage("\033[91m[*]\033[0m %s" % FLAW_IKEV1, args.output)

			try:
				fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\"></flaw>\n" % (flawid, FLAW_IKEV1))
				flawid += 1
			except:
				pass

		# Fingerprinted by VID
		if "vid" in list(vpns[ip].keys()) and len(vpns[ip]["vid"]) > 0:

			printMessage("\033[91m[*]\033[0m %s" % FLAW_FING_VID, args.output)

			for pair in vpns[ip]["vid"]:

				printMessage("\t%s" % pair[0], args.output)
				if VERBOSE:
					printMessage("%s\n" % pair[1], args.output)

				try:
					fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_FING_VID, pair[0], pair[1]))
					flawid += 1
				except:
					pass

		# Fingerprinted by back-off
		if "showbackoff" in list(vpns[ip].keys()) and vpns[ip]["showbackoff"].strip():

			printMessage("\033[91m[*]\033[0m %s: %s" % (FLAW_FING_BACKOFF, vpns[ip]["showbackoff"]), args.output)

			try:
				fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"></flaw>\n" % (flawid, FLAW_FING_BACKOFF, vpns[ip]["showbackoff"]))
				flawid += 1
			except:
				pass

		# Weak encryption/hash/DH group algorithms and auth. methods
		first = True
		if "transforms" in list(vpns[ip].keys()):
			for trio in vpns[ip]["transforms"]:

				if "Enc=DES" in trio[1]:
					if first:
						if not ENC_ANNOUNCEMENT:
							printMessage("\n[*] %s" % ENC_ANNOUNCEMENT_TEXT)
							ENC_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_ENC_DES, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_ENC_DES, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Enc=IDEA" in trio[1]:
					if first:
						if not ENC_ANNOUNCEMENT:
							printMessage("\n[*] %s" % ENC_ANNOUNCEMENT_TEXT)
							ENC_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_ENC_IDEA, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_ENC_IDEA, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Enc=Blowfish" in trio[1]:
					if first:
						if not ENC_ANNOUNCEMENT:
							printMessage("\n[*] %s" % ENC_ANNOUNCEMENT_TEXT)
							ENC_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_ENC_BLOW, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_ENC_BLOW, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Enc=RC5" in trio[1]:
					if first:
						if not ENC_ANNOUNCEMENT:
							printMessage("\n[*] %s" % ENC_ANNOUNCEMENT_TEXT)
							ENC_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_ENC_RC5, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_ENC_RC5, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Enc=CAST" in trio[1]:
					if first:
						if not ENC_ANNOUNCEMENT:
							printMessage("\n[*] %s" % ENC_ANNOUNCEMENT_TEXT)
							ENC_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_ENC_CAST, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_ENC_CAST, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Enc=3DES" in trio[1]:
					if first:
						if not ENC_ANNOUNCEMENT:
							printMessage("\n[*] %s" % ENC_ANNOUNCEMENT_TEXT)
							ENC_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_ENC_3DES, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_ENC_3DES, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Hash=MD5" in trio[1]:
					if first:
						if not HASH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % HASH_ANNOUNCEMENT_TEXT)
							HASH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_HASH_MD5, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_HASH_MD5, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Hash=SHA1" in trio[1]:
					if first:
						if not HASH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % HASH_ANNOUNCEMENT_TEXT)
							HASH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_HASH_SHA1, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_HASH_SHA1, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Group=1:modp768" in trio[1]:
					if first:
						if not KE_ANNOUNCEMENT:
							printMessage("\n[*] %s" % KE_ANNOUNCEMENT_TEXT)
							KE_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_DHG_1, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_DHG_1, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Group=2:modp1024" in trio[1]:
					if first:
						if not KE_ANNOUNCEMENT:
							printMessage("\n[*] %s" % KE_ANNOUNCEMENT_TEXT)
							KE_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_DHG_2, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_DHG_2, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Group=5:modp1536" in trio[1]:
					if first:
						if not KE_ANNOUNCEMENT:
							printMessage("\n[*] %s" % KE_ANNOUNCEMENT_TEXT)
							KE_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_DHG_5, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_DHG_5, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=PSK" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_PSK, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_PSK, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=DSS" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_DSA_SIG, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_DSA_SIG, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=RSA_Sig" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_RSA_SIG, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_RSA_SIG, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=RSA_Enc" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_RSA_ENC, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_RSA_ENC, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=RSA_RevEnc" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_RSA_ENC_REV, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_RSA_ENC_REV, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=ElGamel_Enc" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_ELG_ENC, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_ELG_ENC, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=ElGamel_RevEnc" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_ELG_ENC_REV, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_ELG_ENC_REV, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=ECDSA_Sig" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_ECDSA_SIG, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_ECDSA_SIG, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=ECDSA_SHA256" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_ECDSA_SHA256, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_ECDSA_SHA256, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=ECDSA_SHA384" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_ECDSA_SHA384, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_ECDSA_SHA384, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=ECDSA_SHA512" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_ECDSA_SHA512, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_ECDSA_SHA512, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=CRACK" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_CRACK, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_CRACK, trio[1], trio[2]))
						flawid += 1
					except:
						pass

			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=Hybrid_RSA" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_HYB_RSA, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_HYB_RSA, trio[1], trio[2]))
						flawid += 1
					except:
						pass
			first = True
			for trio in vpns[ip]["transforms"]:

				if "Auth=Hybrid" in trio[1]:
					if first:
						if not AUTH_ANNOUNCEMENT:
							printMessage("\n[*] %s" % AUTH_ANNOUNCEMENT_TEXT)
							AUTH_ANNOUNCEMENT = True
						first = False
						printMessage("\033[91m[*]\033[0m %s" % FLAW_AUTH_HYB_DSA, args.output)

					if VERBOSE:
						printMessage("%s" % trio[2], args.output)

					try:
						fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AUTH_HYB_DSA, trio[1], trio[2]))
						flawid += 1
					except:
						pass

		# Aggressive Mode ?
		if "aggressive" in list(vpns[ip].keys()) and len(vpns[ip]["aggressive"]) > 0:

			printMessage("\033[91m[*]\033[0m %s" % FLAW_AGGR, args.output)

			for trio in vpns[ip]["aggressive"]:

				if VERBOSE:
					printMessage("%s" % (trio[2]), args.output)
				else:
					printMessage("\t%s" % (trio[1]), args.output)

				try:
					fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (flawid, FLAW_AGGR, trio[1], trio[2]))
					flawid += 1
				except:
					pass

			printMessage("\033[91m[*]\033[0m %s" % FLAW_AGGR_GRP_NO_ENC, args.output)
			try:
				fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\"></flaw>\n" % (flawid, FLAW_AGGR_GRP_NO_ENC))
				flawid += 1
			except:
				pass

		# Client IDs ?
		if "clientids" in list(vpns[ip].keys()) and len(vpns[ip]["clientids"]) > 0:

			printMessage("\033[91m[*]\033[0m %s: %s" % (FLAW_CID_ENUM, ", ".join(vpns[ip]["clientids"])), args.output)

			try:
				fxml.write("\t\t\t<flaw flawid=\"%s\" description=\"%s\" value=\"%s\"></flaw>\n" % (flawid, FLAW_CID_ENUM, ", ".join(vpns[ip]["clientids"])))
				flawid += 1
			except:
				pass

		try:
			fxml.write("\t\t</flaws>\n\t</service>\n")
		except:
			pass

	try:
		fxml.write("</services>\n")
		fxml.close()
	except:
		pass


###############################################################################
# Main method of the application
###############################################################################

def main():
	'''This is the main method of the application.'''

	# Say 'hello', check for privileges and ike-scan installation and parse the command line
	welcome()

	if not checkPrivileges():
		print("\033[91m[*]\033[0m This script requires root privileges.")
		exit(1)

	vpns = {}
	args, targets = getArguments()

	if not checkIkeScan():
		print("\033[91m[*]\033[0m ike-scan could not be found. Please specified the full path with the --ikepath option.")
		exit(1)

	startTime = strftime("%a, %d %b %Y %H:%M:%S %Z", localtime())
	printMessage("Starting iker (http://labs.portcullis.co.uk/tools/iker) at %s" % startTime, args.output)

	# 1. Discovery
	discovery(args, targets, vpns)
	checkIKEv2(args, targets, vpns)

	if not len(list(vpns.keys())):
		print("\033[93m[*]\033[0m No IKE service was found.")
		exit(1)

	# 2. Fingerprint by checking VIDs and by analyzing the service responses
	fingerprintVID(args, vpns)
	if not args.nofingerprint:
		fingerprintShowbackoff(args, vpns)

	# 3. Ciphers
	checkEncryptionAlgs(args, vpns)

	# 3.5 Authentication Methods & MFA Detection
	enumerateAuthMethods(args, vpns)

	# 4. Aggressive Mode
	checkAggressive(args, vpns)

	# 5. Enumerate client IDs
	enumerateGroupID(args, vpns)

	# 6. Quick crack attempt
	quickCrack(args, vpns)

	endTime = strftime("%a, %d %b %Y %H:%M:%S %Z", localtime())
	printMessage("iker finished enumerating/brute forcing at %s" % endTime, args.output)

	# 6. Parse the results
	parseResults(args, vpns, startTime, endTime)
	
	# 7. Generate JSON report if requested
	if hasattr(args, 'json') and args.json:
		try:
			scan_metadata = {
				"iker_version": VERSION,
				"start_time": startTime,
				"end_time": endTime,
				"scan_parameters": {
					"encryption_algorithms": ENCLIST,
					"hash_algorithms": HASHLIST,
					"auth_methods": AUTHLIST,
					"key_groups": GROUPLIST,
					"aggressive_mode_tested": True,
					"fingerprinting_enabled": not args.nofingerprint
				}
			}
			
			json_report = generateJsonReport(vpns, scan_metadata)
			
			with open(args.json, 'w') as f:
				f.write(json_report)
			
			print("\033[92m[*]\033[0m JSON report saved to: %s" % args.json)
			
			# Print summary statistics
			report_data = json.loads(json_report)
			print("\033[92m[*]\033[0m Scan Summary:")
			print("\033[92m[*]\033[0m   Total targets: %d" % report_data['summary']['total_targets'])
			print("\033[92m[*]\033[0m   Vulnerable targets: %d" % report_data['summary']['vulnerable_targets'])
			
		except Exception as e:
			print("\033[91m[*]\033[0m Error generating JSON report: %s" % str(e))
	
if __name__ == '__main__':
	main()


# Verde: \033[92m[*]\033[0m
# Rojo: \033[91m[*]\033[0m
# Amarillo: \033[93m[*]\033[0m

# { IP : {
	# "vid" : ["XXXX", ...]
	# "showbackoff
	# "handshake" : ""
	# "transforms" : ["", "", ...]
	# }

# }
