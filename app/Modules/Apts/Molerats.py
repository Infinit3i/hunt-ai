def get_content():
    return {
        "id": "G0021",
        "url_id": "Molerats",
        "title": "Molerats",
        "tags": ["arabic-speaking", "politically motivated", "middle east", "espionage", "cloud abuse"],
        "description": (
            "Molerats is an Arabic-speaking, politically-motivated threat group active since 2012. "
            "Their operations have primarily targeted victims in the Middle East, Europe, and the United States. "
            "They are associated with Operation Molerats and the Gaza Cybergang and have employed a variety of implants, phishing methods, and living-off-the-land techniques."
        ),
        "associated_groups": ["Operation Molerats", "Gaza Cybergang"],
        "campaigns": [],
        "techniques": [
            "T1547.001", "T1059.001", "T1059.005", "T1059.007", "T1555.003",
            "T1140", "T1105", "T1027.015", "T1566.001", "T1566.002",
            "T1057", "T1053.005", "T1553.002", "T1218.007",
            "T1204.001", "T1204.002"
        ],
        "contributors": [],
        "version": "2.1",
        "created": "31 May 2017",
        "last_modified": "17 November 2024",
        "navigator": "",
        "references": [
            {"source": "ClearSky", "url": "https://www.clearskysec.com/operation-dustysky/"},
            {"source": "GReAT", "url": "https://securelist.com/gaza-cybergang-group1-operation-sneakypastes/90112/"},
            {"source": "Cybereason Nocturnus Team", "url": "https://www.cybereason.com/blog/molerats-in-the-cloud"},
            {"source": "Villeneuve et al.", "url": "https://www.fireeye.com/blog/threat-research/2013/08/operation-molerats-middle-east-cyber-attacks-using-poison-ivy.html"},
            {"source": "Falcone et al.", "url": "https://unit42.paloaltonetworks.com/molerats-delivers-spark-backdoor/"}
        ],
        "resources": [],
        "remediation": (
            "Apply strict email filtering, enforce multi-factor authentication, and educate users on recognizing "
            "malicious attachments and links. Implement application whitelisting and monitor scheduled tasks and "
            "msiexec executions."
        ),
        "improvements": (
            "Harden browser credential storage, disable unnecessary scripting interpreters (PowerShell, VBScript, JS), "
            "and proactively scan for unauthorized task scheduling or code-signing anomalies."
        ),
        "hunt_steps": [
            "Hunt for suspicious msiexec.exe executions tied to unknown MSI payloads.",
            "Monitor for registry modifications in Run/Startup keys from unknown executables.",
            "Inspect endpoint logs for PowerShell, VBScript, or JavaScript executions linked to suspicious emails."
        ],
        "expected_outcomes": [
            "Identification of spearphishing delivery methods and initial infection vectors.",
            "Detection of malware families such as DropBook, DustySky, MoleNet, PoisonIvy, SharpStage, and Spark.",
            "Visibility into persistence mechanisms via autoruns and scheduled tasks."
        ],
        "false_positive": (
            "Legitimate use of PowerShell and msiexec.exe by administrators may overlap with attacker behavior. "
            "Baseline normal usage and apply behavioral analytics for context-aware detection."
        ),
        "clearing_steps": [
            "Remove malicious scheduled tasks and scripts from startup folders.",
            "Delete malware implants and related files from affected systems.",
            "Revoke access tokens or credentials compromised via phishing.",
            "Check and restore affected registry keys and group policy settings."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
