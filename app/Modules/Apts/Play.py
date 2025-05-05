def get_content():
    return {
        "id": "G1040",
        "url_id": "Play",
        "title": "Play",
        "tags": [
            "ransomware", "double extortion", "Playcrypt", "Cobalt Strike", "Mimikatz",
            "critical infrastructure", "Europe", "North America", "South America", "2022+"
        ],
        "description": (
            "Play is a ransomware group active since at least 2022 that primarily targets business, government, "
            "critical infrastructure, healthcare, and media sectors across North America, South America, and Europe. "
            "Play is known for its double-extortion tactics: stealing data and encrypting systems, then threatening to "
            "release stolen information if the ransom is not paid. The group uses Playcrypt ransomware and a range of tools "
            "for discovery, credential dumping, defense evasion, and data exfiltration. Notably, it has leveraged Cobalt Strike, "
            "WinRAR, WinSCP, and various obfuscated PowerShell scripts."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1560.001", "T1059.001", "T1059.003", "T1030", "T1587.001", "T1048", "T1190",
            "T1133", "T1083", "T1657", "T1562.001", "T1070.001", "T1070.004", "T1105",
            "T1027.010", "T1588.002", "T1003.001", "T1057", "T1021.002", "T1018",
            "T1518.001", "T1082", "T1016", "T1078", "T1078.002", "T1078.003"
        ],
        "contributors": ["Marco Pedrinazzi"],
        "version": "1.0",
        "created": "24 September 2024",
        "last_modified": "02 October 2024",
        "navigator": "",
        "references": [
            {
                "source": "CISA AA23-352A",
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"
            },
            {
                "source": "Trend Micro Play Ransomware Spotlight",
                "url": "https://www.trendmicro.com/en_us/research/23/g/play-ransomware-spotlight.html"
            }
        ],
        "resources": [],
        "remediation": (
            "Apply patches for known exploited vulnerabilities (e.g., FortiOS and Exchange CVEs). "
            "Disable unused services and enforce network segmentation to reduce lateral movement opportunities. "
            "Monitor for use of dual-use tools like Cobalt Strike, WinRAR, and WinSCP. "
            "Restrict RDP and VPN access with MFA and robust logging."
        ),
        "improvements": (
            "Deploy EDR to track use of credential dumping tools and command-line obfuscation. "
            "Harden system configurations to prevent LSASS memory access. "
            "Establish threat hunting routines for Play TTPs including PowerShell encoded commands and SMB lateral transfers."
        ),
        "hunt_steps": [
            "Search for Base64-encoded PowerShell commands that modify Defender settings.",
            "Hunt for usage of tools like AdFind, Nltest, BloodHound in unusual locations.",
            "Inspect SMB lateral movements via PsExec or Cobalt Strike artifacts.",
            "Look for Wevtutil or batch script usage tied to log or file deletion."
        ],
        "expected_outcomes": [
            "Detection of ransomware staging, credential dumping, and exfiltration prior to encryption.",
            "Identification of network discovery tools indicative of lateral movement.",
            "Evidence of attempted defense evasion through AV tool tampering or log cleansing."
        ],
        "false_positive": (
            "Legitimate admin use of PowerShell, SMB, or WinRAR may resemble attacker behavior. "
            "Validate command context and process lineage before triggering alerts."
        ),
        "clearing_steps": [
            "Revoke compromised domain, local, and VPN credentials.",
            "Clear malicious scheduled tasks, registry keys, and persistence scripts.",
            "Restore from backups and patch exploited vulnerabilities immediately.",
            "Purge malware binaries, encoded scripts, and lateral tools such as Playcrypt and Cobalt Strike loaders."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
