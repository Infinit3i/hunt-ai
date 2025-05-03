def get_content():
    return {
        "id": "G0078",
        "url_id": "Gorgon_Group",
        "title": "Gorgon Group",
        "tags": ["Pakistan", "cybercrime", "espionage", "government targeting"],
        "description": "Gorgon Group is a suspected Pakistan-based threat actor known for blending criminal and targeted cyber operations. The group has conducted campaigns against government organizations in the United Kingdom, Spain, Russia, and the United States. Their operations often involve spearphishing, payload obfuscation, persistence mechanisms, and the use of commodity RATs such as QuasarRAT and Remcos.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1547.001", "T1547.009", "T1059.001", "T1059.003", "T1059.005", "T1140", "T1564.003",
            "T1562.001", "T1105", "T1112", "T1106", "T1588.002", "T1566.001", "T1055.002", "T1055.012",
            "T1204.002"
        ],
        "contributors": [],
        "version": "1.5",
        "created": "17 October 2018",
        "last_modified": "16 April 2025",
        "navigator": "",  # Add ATT&CK Navigator link if applicable
        "references": [
            {
                "source": "Falcone, R., et al.",
                "url": "https://unit42.paloaltonetworks.com/the-gorgon-group-slithering-between-nation-state-and-cybercrime/"
            }
        ],
        "resources": [],
        "remediation": "Block execution of VBS and macro-based documents. Monitor for shortcut (.lnk) creation in startup directories. Harden registry and script execution policies. Restrict access to known C2 domains used by commodity RATs.",
        "improvements": "Add detections for shortcut-based persistence. Watch for PowerShell execution with hidden windows. Deploy YARA or behavioral signatures for RATs like QuasarRAT, Remcos, and NanoCore.",
        "hunt_steps": [
            "Hunt for registry modifications under Office and Windows Defender keys.",
            "Look for PowerShell usage with `-WindowStyle Hidden` or `-W Hidden` flags.",
            "Search for `.lnk` files in startup paths or suspicious Run key values.",
            "Correlate attachments in spearphishing emails with execution events on endpoints."
        ],
        "expected_outcomes": [
            "Detection of early-stage phishing-based infections.",
            "Disruption of persistence via shortcut files and registry keys.",
            "Identification of commodity RAT use and lateral movement attempts."
        ],
        "false_positive": "Shortcut creation and registry edits may occur during legitimate software installations. Validate with surrounding behavior and context.",
        "clearing_steps": [
            "Delete malicious shortcut files and Run key entries.",
            "Remove downloaded RAT binaries and encoded payloads.",
            "Re-enable security features disabled in Office or Defender.",
            "Isolate and reimage infected machines where process injection occurred."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
