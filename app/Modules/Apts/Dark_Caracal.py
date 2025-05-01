def get_content():
    return {
        "id": "G0070",
        "url_id": "Dark_Caracal",
        "title": "Dark Caracal",
        "tags": ["lebanese", "GDGS", "state-sponsored", "cyber-espionage", "bandook", "mobile", "desktop"],
        "description": "Dark Caracal is a threat group attributed to the Lebanese General Directorate of General Security (GDGS). Active since at least 2012, the group has targeted both mobile and desktop platforms globally using malware such as Bandook, CrossRAT, FinFisher, and Pallas.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1071.001", "T1547.001", "T1059.003", "T1005", "T1189", "T1083",
            "T1027.002", "T1027.013", "T1566.003", "T1113", "T1218.001", "T1204.002",
            "T1437.001"
        ],
        "contributors": [],
        "version": "1.4",
        "created": "17 October 2018",
        "last_modified": "11 April 2024",
        "navigator": "",
        "references": [
            {"source": "Lookout & EFF", "url": "https://www.lookout.com/documents/threat-reports/lookout-dark-caracal-report.pdf"},
            {"source": "Check Point", "url": "https://research.checkpoint.com/2020/bandook-signed-and-delivered/"}
        ],
        "resources": ["Dark Caracal global espionage report", "Bandook signed malware analysis"],
        "remediation": "Apply strict application control and block execution of untrusted HTML and document files. Harden mobile device policies and prohibit installation of unverified apps.",
        "improvements": "Enhance detection of obfuscated files, including UPX-packed or Base64-encrypted binaries. Monitor command line usage of common tools like `reg`, `cmd.exe`, and file discovery commands.",
        "hunt_steps": [
            "Search for registry entries under HKEY_USERS for suspicious Run keys.",
            "Identify malicious CHM file executions via `hh.exe` or compiled HTML files.",
            "Hunt for PowerShell or command shell activity triggered by Office macros.",
            "Detect large screen capture logs or encoded traffic over HTTP with unusual suffixes like '&&&'."
        ],
        "expected_outcomes": [
            "Detection of Bandook malware activity across Windows hosts.",
            "Identification of spearphishing delivery via Facebook or WhatsApp.",
            "Discovery of persistent registry-based startup items.",
            "Exposure of obfuscated or encrypted payload staging techniques."
        ],
        "false_positive": "Legitimate UPX-packed software or HTTP traffic with encoded payloads might appear similar. Validate with process lineage and payload behavior.",
        "clearing_steps": [
            "Remove persistence keys in registry.",
            "Terminate and remove Bandook, CrossRAT, or Pallas malware artifacts.",
            "Block IPs and domains used for C2 identified in malware samples.",
            "Review mobile device security policies and wipe compromised phones if needed."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
