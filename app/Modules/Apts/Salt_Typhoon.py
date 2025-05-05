def get_content():
    return {
        "id": "G1045",
        "url_id": "Salt_Typhoon",
        "title": "Salt Typhoon",
        "tags": ["china", "telecommunications", "isp", "network-infrastructure", "prc", "state-sponsored", "router-targeting"],
        "description": (
            "Salt Typhoon is a Chinese state-sponsored threat actor active since at least 2019. The group is known for compromising "
            "network infrastructure at major U.S. telecommunications and internet service providers. Salt Typhoon leverages public and custom-developed tools "
            "to access, manipulate, and exfiltrate configuration data from routers and switches, often establishing persistent access through user and SSH key manipulation. "
            "Notably, the group has exploited vulnerabilities such as CVE-2018-0171 in Cisco IOS systems and has used GRE tunnels to move laterally within victim networks."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1098.004", "T1110.002", "T1136", "T1602.002", "T1587.001",
            "T1048.003", "T1190", "T1590.004", "T1562.004", "T1070.002",
            "T1040", "T1588.002", "T1572", "T1021.004"
        ],
        "contributors": [],
        "version": "1.0",
        "created": "24 February 2025",
        "last_modified": "06 March 2025",
        "navigator": "",
        "references": [
            {
                "source": "US Department of Treasury",
                "url": "https://home.treasury.gov/news/press-releases/jy2000"
            },
            {
                "source": "Cisco Talos",
                "url": "https://blog.talosintelligence.com/weathering-the-storm-salt-typhoon/"
            }
        ],
        "resources": [],
        "remediation": (
            "Update and harden configurations of Cisco IOS and other exposed infrastructure. Patch vulnerabilities such as CVE-2018-0171. "
            "Monitor for unauthorized modifications to ACLs, loopback interfaces, and SSH keys. Enforce multi-factor authentication and "
            "rotate credentials regularly, especially for infrastructure accounts."
        ),
        "improvements": (
            "Improve logging granularity on network appliances. Deploy anomaly-based IDS/IPS for lateral movement indicators. "
            "Monitor for GRE tunnel usage and control routing protocols to detect tampering or misuse."
        ),
        "hunt_steps": [
            "Check /etc/passwd and /etc/shadow for unexpected user entries on networking devices.",
            "Review SSH authorized_keys files for unauthorized additions.",
            "Monitor syslog and SNMP traps for config changes such as ACL updates or GRE tunnel creation.",
            "Inspect device configurations for modifications to loopback interfaces and GRE tunnels.",
            "Search for use of TFTP/FTP services used during odd hours or from non-standard IPs."
        ],
        "expected_outcomes": [
            "Detection of persistence mechanisms involving user and SSH key creation.",
            "Identification of malicious configuration changes to ACLs, loopback interfaces, and tunneling protocols.",
            "Increased awareness of targeted infrastructure vulnerabilities and lateral movement techniques."
        ],
        "false_positive": (
            "Administrative SSH key usage and GRE tunnel configuration may be legitimate in some environments. Validation should include review of associated change tickets or approval logs."
        ),
        "clearing_steps": [
            "Revoke and rotate all SSH credentials on compromised devices.",
            "Remove unauthorized user accounts and keys.",
            "Restore firewall/ACL configurations to known-good baselines.",
            "Purge malicious configurations and remove tunneling entries from running and startup configs.",
            "Clean relevant logs if attacker log tampering is detected."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
