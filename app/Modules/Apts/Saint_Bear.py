def get_content():
    return {
        "id": "G1031",
        "url_id": "Saint_Bear",
        "title": "Saint Bear",
        "tags": ["russia", "phishing", "ukraine", "georgia", "outsteel", "saintbot", "government-impersonation"],
        "description": (
            "Saint Bear is a Russian-nexus threat group active since early 2021, known for cyber operations primarily targeting entities in Ukraine and Georgia. "
            "The group employs a range of spearphishing techniques involving spoofed government-themed content and weaponized documents. "
            "Saint Bear commonly delivers its custom malware payloads—OutSteel (document exfiltration tool) and Saint Bot (modular post-exploitation loader)—via phishing attachments or web links hosted on legitimate platforms like Discord CDN. "
            "Despite earlier confusion with Ember Bear, behavioral distinctions and unique tooling mark Saint Bear as a distinct intrusion cluster."
        ),
        "associated_groups": ["Storm-0587", "TA471", "UAC-0056", "Lorec53"],
        "campaigns": [],
        "techniques": [
            "T1583.006", "T1059", "T1059.001", "T1059.003", "T1059.007",
            "T1203", "T1589.002", "T1562.001", "T1656", "T1112",
            "T1027.002", "T1027.013", "T1566.001", "T1608.001", "T1553.002",
            "T1204.001", "T1204.002", "T1497"
        ],
        "contributors": ["Unit 42", "Microsoft Threat Intelligence"],
        "version": "1.0",
        "created": "25 May 2024",
        "last_modified": "12 August 2024",
        "navigator": "",
        "references": [
            {
                "source": "Unit 42",
                "url": "https://unit42.paloaltonetworks.com/spear-phishing-attacks-ukraine-outsteel-saintbot/"
            },
            {
                "source": "Microsoft Threat Intelligence",
                "url": "https://www.microsoft.com/en-us/security/blog/2023/06/14/cadet-blizzard-emerges-russian-threat-actor/"
            }
        ],
        "resources": [],
        "remediation": (
            "Block access to known Saint Bear infrastructure, including Discord CDN links used for malware hosting. Monitor and restrict execution of scripting environments "
            "such as PowerShell, WScript, and CMD. Apply patches for Microsoft Office vulnerabilities like CVE-2017-11882 and implement sandbox analysis for attachments."
        ),
        "improvements": (
            "Enrich anti-phishing detection with indicators of spoofed government branding and document lure themes. Harden endpoint defenses to block macro-enabled Office documents "
            "and enforce AMSI for PowerShell. Use network segmentation to reduce post-compromise mobility."
        ),
        "hunt_steps": [
            "Review email logs and endpoints for attachments or links using Discord CDN or spoofed government sender names.",
            "Analyze registry modifications related to Microsoft Defender and script-blocking policies.",
            "Detect PowerShell or wscript/cmd execution from user folders or temp directories.",
            "Look for usage of code signing certificates from entities like 'Electrum Technologies GmbH'.",
            "Search for indicators of OutSteel and Saint Bot executables or DLL injections.",
            "Inspect for virtual environment evasion logic in malware behavior."
        ],
        "expected_outcomes": [
            "Early detection of phishing lures and staged payloads hosted on abused web services.",
            "Blocking of C2 communications and identification of post-exploitation tooling.",
            "Awareness of targeting patterns against government, defense, and civil sector institutions in Ukraine/Georgia.",
            "Minimized risk from privilege escalation and lateral movement by blocking initial script execution."
        ],
        "false_positive": (
            "Use of PowerShell or batch scripts may be legitimate. Validate the script origin, hash, and execution context before triggering alerts."
        ),
        "clearing_steps": [
            "Isolate affected systems and remove all files associated with OutSteel and Saint Bot.",
            "Reinstate Microsoft Defender functionality if modified, and revert affected registry and task entries.",
            "Reset credentials used during phishing stages and rotate any accessed session tokens.",
            "Audit outbound traffic to Discord CDN and GitHub for malware hosting abuse."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
