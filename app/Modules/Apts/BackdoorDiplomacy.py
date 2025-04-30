def get_content():
    return {
        "id": "G0135",
        "url_id": "BackdoorDiplomacy",
        "title": "BackdoorDiplomacy",
        "tags": ["cyberespionage", "telecom", "foreign-affairs", "africa", "middle-east", "asia", "europe"],
        "description": "BackdoorDiplomacy is a cyber espionage group active since at least 2017. The group has targeted Ministries of Foreign Affairs and telecommunications organizations across Africa, Europe, the Middle East, and Asia. They are known for exploiting public-facing applications, deploying custom malware, and leveraging tools like EarthWorm and Turian.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1074.001", "T1190", "T1574.001", "T1105", "T1036.004", "T1036.005", "T1046", "T1095",
            "T1027", "T1588.001", "T1588.002", "T1120", "T1055.001", "T1505.003", "T1049"
        ],
        "contributors": ["Zaw Min Htun", "@Z3TAE"],
        "version": "1.0",
        "created": "21 September 2021",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Adam Burgher",
                "url": "https://www.welivesecurity.com/2021/06/10/backdoordiplomacy-upgrading-from-quarian-to-turian/"
            }
        ],
        "resources": [],
        "remediation": "Patch internet-facing systems regularly, particularly those using F5 BIG-IP or Plesk. Harden access to web shells and monitor for suspicious DLL activity. Disable unused protocols like SMBv1 and ensure endpoint monitoring tools can detect obfuscation and tunneling activity.",
        "improvements": "Develop alerting for DLL search-order hijacking patterns, local file staging in unusual directories (e.g., Recycle Bin), and obfuscated executables protected with VMProtect. Incorporate behavior-based analytics for tunneling tools like EarthWorm and tools like QuasarRAT.",
        "hunt_steps": [
            "Search for suspicious binaries in recycle bin paths",
            "Hunt for VMProtect-obfuscated binaries and packed malware",
            "Check for unexpected NetCat or PortQry usage in non-admin contexts",
            "Inspect task and service names for masquerading behaviors",
            "Identify signs of EarthWorm-based tunneling activity"
        ],
        "expected_outcomes": [
            "Detection of staged files prior to exfiltration",
            "Discovery of malicious DLL sideloading activity",
            "Identification of persistence via masqueraded services",
            "Evidence of SOCKS5 tunneling or shell access via web shells"
        ],
        "false_positive": "Recycled files and legitimate DLLs in expected locations may trigger detection. Validate usage patterns and metadata before confirming malicious behavior.",
        "clearing_steps": [
            "Delete web shells and remove persistence mechanisms",
            "Clean up staged exfiltration data in temporary or recycle directories",
            "Remove malicious services or renamed binaries",
            "Block outbound tunneling and remove EarthWorm executables",
            "Restore clean versions of hijacked legitimate DLLs"
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
