def get_content():
    return {
        "id": "G1018",
        "url_id": "TA2541",
        "title": "TA2541",
        "tags": ["cybercrime", "aviation", "asyncRAT", "commoditized", "phishing", "transportation"],
        "description": (
            "TA2541 is a cybercriminal group active since at least 2017, known for targeting aviation, aerospace, transportation, "
            "manufacturing, and defense sectors. Their campaigns are typically high-volume and utilize commodity remote access tools "
            "delivered through phishing emails, often themed around travel or logistics. The group frequently uses cloud services, "
            "dynamic DNS, and encrypted channels to deliver and control malware payloads."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1583.001", "T1583.006", "T1547.001", "T1059.001", "T1059.005", "T1568", "T1573.002", "T1562.001", "T1105",
            "T1036.005", "T1027.002", "T1027.013", "T1027.015", "T1588.001", "T1588.002", "T1566.001", "T1566.002", 
            "T1055", "T1055.012", "T1053.005", "T1518.001", "T1608.001", "T1218.005", "T1082", "T1016.001", "T1204.001", 
            "T1204.002", "T1047"
        ],
        "contributors": ["Pooja Natarajan, NEC Corporation India", "Aaron Jornet"],
        "version": "1.1",
        "created": "12 September 2023",
        "last_modified": "10 April 2024",
        "navigator": "",
        "references": [
            {
                "source": "Proofpoint - Charting TA2541’s Flight",
                "url": "https://www.proofpoint.com/us/blog/threat-insight/charting-ta2541s-flight"
            },
            {
                "source": "Intezer - Operation Layover",
                "url": "https://www.intezer.com/blog/research/operation-layover/"
            }
        ],
        "resources": [],
        "remediation": (
            "Implement advanced email filtering and sandboxing to detect phishing attachments and links. "
            "Restrict macro execution and script interpreters (e.g., PowerShell, mshta) to administrative use only. "
            "Monitor cloud and DNS traffic for signs of abuse involving platforms like Google Drive, PasteText, and No-IP."
        ),
        "improvements": (
            "Use threat intelligence to block known TA2541 infrastructure and malware hashes. "
            "Deploy EDR solutions capable of detecting process injection and obfuscation techniques. "
            "Harden endpoint defenses against commodity RATs (e.g., AsyncRAT, njRAT, WarzoneRAT)."
        ),
        "hunt_steps": [
            "Search for outbound connections to Discord, OneDrive, Google Drive, or No-IP domains.",
            "Look for execution of mshta.exe, PowerShell, or VBS scripts from unusual directories or by non-admin users.",
            "Scan for persistence mechanisms in registry Run keys or scheduled tasks.",
            "Check for known AsyncRAT or WarzoneRAT behavior such as process hollowing or encoded PowerShell payloads."
        ],
        "expected_outcomes": [
            "Identification of phishing attempts and malware download activity.",
            "Detection of persistence mechanisms associated with VBS, scheduled tasks, or registry run keys.",
            "Flagging of obfuscated commodity malware loading via cloud services or native Windows binaries."
        ],
        "false_positive": (
            "Legitimate use of cloud services and scripting tools may trigger alerts. "
            "Review execution context, timing, and originating user before escalating."
        ),
        "clearing_steps": [
            "Remove persistence artifacts (startup VBS files, registry keys, scheduled tasks).",
            "Terminate RAT connections and quarantine infected endpoints.",
            "Reset credentials and implement network segmentation to prevent lateral movement."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
