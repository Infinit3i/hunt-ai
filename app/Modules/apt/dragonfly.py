def get_content():
    return {
        "id": "G0035",  # APT Group ID
        "url_id": "G0035",  # URL segment for group reference
        "title": "Dragonfly",  # Name of the APT group
        "tags": ["cyber espionage", "state-sponsored", "Russia", "FSB", "critical infrastructure"],
        "description": (
            "Dragonfly is a cyber espionage group attributed to Russia's Federal Security Service (FSB) Center 16. "
            "Active since at least 2010, Dragonfly has targeted defense and aviation companies, government entities, "
            "industrial control systems, and critical infrastructure sectors worldwide through supply chain, spearphishing, "
            "and drive-by compromise attacks."
        ),
        "associated_groups": [
            "TEMP.Isotope",
            "DYMALLOY",
            "Berserk Bear",
            "TG-4192",
            "Crouching Yeti",
            "IRON LIBERTY",
            "Energetic Bear",
            "Ghost Blizzard",
            "BROMINE"
        ],
        "campaigns": [
            # Campaign details can be added here if available.
        ],
        "techniques": [
            "T1087.002",  # Account Discovery: Domain Account – Batch scripts to enumerate users on victim domain controllers
            "T1098.007",  # Account Manipulation: Additional Local or Domain Groups – Added new accounts to administrator groups
            "T1583.001",  # Acquire Infrastructure: Domains – Registered domains for targeting victims
            "T1583.003",  # Acquire Infrastructure: Virtual Private Server – Acquired VPS infrastructure for campaigns
            "T1595.002",  # Active Scanning: Vulnerability Scanning – Scanned for vulnerable Citrix and MS Exchange services
            "T1071.002",  # Application Layer Protocol: File Transfer Protocols – Used SMB for C2 communications
            "T1560.001",  # Archive Collected Data – Compressed data into .zip files prior to exfiltration
            "T1547.001",  # Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder – Added registry value for persistence
            "T1110",      # Brute Force – Attempted brute force attacks for credential access
            "T1110.002",  # Password Cracking – Dropped and executed password cracking tools (e.g., Hydra, CrackMapExec)
            "T1059.001",  # Command and Scripting Interpreter: PowerShell – Used PowerShell scripts for execution
            "T1059.003",  # Command and Scripting Interpreter: Windows Command Shell – Employed batch scripts for operations
            "T1059.006",  # Command and Scripting Interpreter: Python – Observed installing and using Python 2.7
            "T1584.004",  # Compromise Infrastructure: Server – Compromised legitimate websites to host C2 and malware modules
            "T1136.001",  # Create Account: Local Account – Created tailored local accounts on victim systems
            "T1005",      # Data from Local System – Collected data from local victim systems
            "T1074.001",  # Data Staged: Local Data Staging – Created an "out" directory in %AppData% for file staging
            "T1189",      # Drive-by Compromise – Compromised targets via strategic web compromise using an exploit kit
            "T1114.002",  # Email Collection: Remote Email Collection – Accessed email accounts via Outlook Web Access
            "T1190",      # Exploit Public-Facing Application – Conducted SQL injection and exploited multiple vulnerabilities (e.g., CVE-2019-19781, CVE-2020-0688, CVE-2018-13379)
            "T1203",      # Exploitation for Client Execution – Exploited CVE-2011-0611 in Adobe Flash Player
            "T1210",      # Exploitation of Remote Services – Exploited Windows Netlogon vulnerability (CVE-2020-1472)
            "T1133",      # External Remote Services – Used VPNs and Outlook Web Access to maintain network access
            "T1083",      # File and Directory Discovery – Gathered folder and file names via batch scripts
            "T1187",      # Forced Authentication – Collected hashed credentials over SMB using modified .LNK file resources
            "T1591.002",  # Gather Victim Org Information: Business Relationships – Collected open source information on organizational relationships
            "T1564.002",  # Hide Artifacts: Hidden Users – Modified Registry to hide created user accounts
            "T1562.004",  # Impair Defenses: Disable or Modify System Firewall – Disabled host-based firewalls and opened port 3389
            "T1070.001",  # Indicator Removal: Clear Windows Event Logs – Cleared Windows and audit logs
            "T1070.004",  # Indicator Removal: File Deletion – Deleted files used during operations, including cleanup of screenshots
            "T1105",      # Ingress Tool Transfer – Copied and installed tools for post-compromise operations
            "T1036.010",  # Masquerading: Masquerade Account Name – Created accounts disguised as legitimate backup/service accounts
            "T1112",      # Modify Registry – Modified the Registry for multiple techniques via Reg commands
            "T1135",      # Network Share Discovery – Identified and browsed file servers, including ICS/SCADA systems
            "T1588.002",  # Obtain Capabilities: Tool – Obtained and used tools (e.g., Mimikatz, CrackMapExec, PsExec)
            "T1003.002",  # OS Credential Dumping: Security Account Manager – Executed SecretsDump for password hashes
            "T1003.003",  # OS Credential Dumping: NTDS – Dumped ntds.dit from domain controllers
            "T1003.004",  # OS Credential Dumping: LSA Secrets – Executed SecretsDump to dump LSA secrets
            "T1069.002",  # Permission Groups Discovery: Domain Groups – Enumerated administrators and users via batch scripts
            "T1566.001",  # Phishing: Spearphishing Attachment – Sent emails with malicious attachments for initial access
            "T1598.002",  # Phishing for Information: Spearphishing Attachment – Used Microsoft Office attachments to harvest credentials
            "T1598.003",  # Phishing for Information: Spearphishing Link – Employed PDF attachments with malicious links for credential harvesting
            "T1012",      # Query Registry – Queried the Registry to extract victim information
            "T1021.001",  # Remote Services: Remote Desktop Protocol – Moved laterally via RDP
            "T1018",      # Remote System Discovery – Obtained a list of hosts in victim environments
            "T1053.005",  # Scheduled Task/Job: Scheduled Task – Used scheduled tasks to log out created accounts and execute malicious files
            "T1113",      # Screen Capture – Performed screen captures using tools such as scr.exe (ScreenUtil)
            "T1505.003",  # Server Software Component: Web Shell – Deployed web shells on publicly accessible servers
            "T1608.004",  # Stage Capabilities: Drive-by Target – Compromised websites to host exploit kits and redirect traffic
            "T1195.002",  # Supply Chain Compromise: Compromise Software Supply Chain – Placed trojanized installers on legitimate vendor app stores
            "T1016",      # System Network Configuration Discovery – Enumerated network configuration via batch scripts
            "T1033",      # System Owner/User Discovery – Used command-line tools (e.g., query user) for discovery
            "T1221",      # Template Injection – Injected SMB URLs into malicious Word spearphishing attachments
            "T1204.002",  # User Execution: Malicious File – Used spearphishing to prompt users into executing malicious files
            "T1078",      # Valid Accounts – Compromised credentials and used valid accounts for operations
            "ICS-T0817",  # ICS: Drive-by Compromise – Utilized watering hole attacks on energy sector websites
            "ICS-T0862"   # ICS: Supply Chain Compromise – Trojanized software packages from legitimate ICS equipment providers
        ],
        "contributors": [
            "Dragos Threat Intelligence"
        ],
        "version": "4.0",
        "created": "31 May 2017",
        "last_modified": "08 January 2024",
        "references": [
            {"source": "MITRE ATT&CK", "url": "https://attack.mitre.org/groups/G0035/"},
            {"source": "Department of Justice (2022, March 24)", "url": "https://www.justice.gov/"},
            {"source": "UK Gov. (2022, April 5)", "url": "https://www.gov.uk/"},
            {"source": "Symantec Security Response (2014, June 30)", "url": "https://www.symantec.com/"},
            {"source": "Secureworks (2019, July 24)", "url": "https://www.secureworks.com/"},
            {"source": "Symantec Security Response (2014, July 7)", "url": "https://www.symantec.com/"},
            {"source": "Hackett, R. (2017, September 6)", "url": "https://www.example.com/"},
            {"source": "Slowik, J. (2021, October)", "url": "https://www.example.com/"},
            {"source": "CISA (2020, December 1)", "url": "https://www.cisa.gov/"},
            {"source": "Hultquist, J. (2022, January 20)", "url": "https://www.example.com/"},
            {"source": "Dragos (n.d.)", "url": "https://www.dragos.com/"},
            {"source": "Secureworks (2019, July 24) – MCMD Malware Analysis", "url": "https://www.secureworks.com/"},
            {"source": "Secureworks (2019, July 24) – Updated Karagany Malware Targets Energy Sector", "url": "https://www.secureworks.com/"},
            {"source": "Microsoft (2023, July 12)", "url": "https://www.microsoft.com/"},
            {"source": "US-CERT (2018, March 16)", "url": "https://www.us-cert.gov/"},
            {"source": "Kali (2014, February 18)", "url": "https://www.kali.org/"},
            {"source": "Core Security (n.d.) – Impacket", "url": "https://www.coresecurity.com/"},
            {"source": "Symantec Security Response (2014, July 7)", "url": "https://www.symantec.com/"}
        ],
        "resources": [
            "https://attack.mitre.org/groups/G0035/"
        ],
        "remediation": "",  # Recommended actions to mitigate risks posed by this APT
        "improvements": "",  # Suggestions for enhancing detection and response related to this APT
        "hunt_steps": [],  # Proactive threat hunting steps to look for indicators of this APT
        "expected_outcomes": [],  # Expected outcomes/results from threat hunting against this APT
        "false_positive": "",  # Known false positives and guidance on handling them
        "clearing_steps": [],  # Steps for remediation and clearing traces from affected systems
        "ioc": {  # Indicators of Compromise (IOCs)
            "sha256": [],  # List of SHA256 hash values
            "md5": [],     # List of MD5 hash values
            "ip": [],      # List of IP addresses associated with the APT
            "domain": [],  # List of domains associated with the APT
            "resources": []  # Additional resources or references for IOCs if applicable
        }
    }
