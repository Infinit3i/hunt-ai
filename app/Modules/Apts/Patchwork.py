def get_content():
    return {
        "id": "G0040",
        "url_id": "Patchwork",
        "title": "Patchwork",
        "tags": [
            "India-attribution", "espionage", "government", "diplomatic", 
            "think-tank", "QuasarRAT", "BADNEWS", "Dropping Elephant", "Hangover Group"
        ],
        "description": (
            "Patchwork is a cyber espionage group first identified in December 2015 and is suspected to be of Indian origin, "
            "possibly linked to the Hangover Group and Operation MONSOON. The group is known for targeting diplomatic, governmental, and think tank entities, "
            "with its campaigns primarily driven through spearphishing and file-based malware delivery. Patchwork is characterized by its use of copy-pasted code "
            "from online forums, use of multiple commodity and custom tools, and wide technique coverage across initial access, execution, persistence, defense evasion, and exfiltration."
        ),
        "associated_groups": [
            "Hangover Group", "Dropping Elephant", "Chinastrats", "MONSOON", "Operation Hangover"
        ],
        "campaigns": [],
        "techniques": [
            "T1548.002", "T1560", "T1119", "T1197", "T1547.001", "T1059.001", "T1059.003", "T1059.005",
            "T1555.003", "T1132.001", "T1005", "T1074.001", "T1587.002", "T1189", "T1203", "T1083",
            "T1574.001", "T1070.004", "T1105", "T1559.002", "T1036.005", "T1112", "T1027.001", "T1027.002",
            "T1027.005", "T1027.010", "T1588.002", "T1566.001", "T1566.002", "T1598.003", "T1055.012",
            "T1021.001", "T1053.005", "T1518.001", "T1553.002", "T1082", "T1033", "T1204.001", "T1204.002",
            "T1102.001"
        ],
        "contributors": [],
        "version": "1.5",
        "created": "31 May 2017",
        "last_modified": "17 November 2024",
        "navigator": "",
        "references": [
            {"source": "Cymmetria", "url": "https://www.cymmetria.com/patchwork-report"},
            {"source": "Kaspersky", "url": "https://securelist.com/dropping-elephant/"},
            {"source": "Palo Alto Networks", "url": "https://unit42.paloaltonetworks.com/patchwork-delivers-badnews/"},
            {"source": "Cybereason", "url": "https://www.cybereason.com/blog/patchwork-apt-targets-think-tanks"}
        ],
        "resources": [],
        "remediation": (
            "Ensure all Office applications are updated and macros are disabled by default. "
            "Limit access to RDP and enforce strong credential policies. "
            "Use digital certificate validation policies to reject self-signed certificates."
        ),
        "improvements": (
            "Deploy behavioral detection for scripting engine abuse (PowerShell, WScript, etc). "
            "Monitor scheduled task creation and unauthorized registry key additions. "
            "Alert on obfuscated script execution or excessive use of binary padding."
        ),
        "hunt_steps": [
            "Search for startup folders or Registry Run keys with suspicious binaries like 'Net Monitor' or 'Baidu Software Update'.",
            "Check for known packed files using UPX and altered hashes.",
            "Inspect outbound HTTP traffic for base64 C2 traffic or comment-hidden URLs from dead drop resolvers."
        ],
        "expected_outcomes": [
            "Identification of persistence through startup folders or registry keys.",
            "Detection of QuasarRAT variants or BADNEWS payloads.",
            "Exfiltration staging directories with collected sensitive documents."
        ],
        "false_positive": (
            "Scheduled tasks and registry modifications may be part of legitimate admin tasks. "
            "Correlate with execution chains or suspicious parent-child process trees to reduce noise."
        ),
        "clearing_steps": [
            "Terminate and remove all known malware components (e.g., BADNEWS, QuasarRAT, AutoIt backdoor).",
            "Delete persistence entries from Startup folders and Registry.",
            "Rotate any compromised credentials and review access logs for lateral movement."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
