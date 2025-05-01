def get_content():
    return {
        "id": "G0079",
        "url_id": "DarkHydrus",
        "title": "DarkHydrus",
        "tags": ["middle-east", "government", "education", "open-source", "credential-harvesting", "spearphishing"],
        "description": "DarkHydrus is a threat group active since at least 2016 that targets government agencies and educational institutions in the Middle East. The group heavily utilizes open-source tools and custom payloads. It is known for spearphishing attacks leveraging malicious templates and Excel Web Query files, credential harvesting, and stealthy execution via PowerShell.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1059.001", "T1187", "T1564.003", "T1588.002", "T1566.001", "T1221", "T1204.002"
        ],
        "contributors": ["Oleg Skulkin", "Group-IB"],
        "version": "1.3",
        "created": "17 October 2018",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "Unit 42", "url": "https://unit42.paloaltonetworks.com/unit42-playbook-viewer/"},
            {"source": "Falcone, R.", "url": "https://unit42.paloaltonetworks.com/new-threat-actor-group-darkhydrus-targets-middle-east-government/"},
            {"source": "Falcone, R.", "url": "https://unit42.paloaltonetworks.com/darkhydrus-uses-phishery-to-harvest-credentials-in-the-middle-east/"},
            {"source": "Lee, B., Falcone, R.", "url": "https://unit42.paloaltonetworks.com/darkhydrus-delivers-new-trojan-that-can-use-google-drive-for-c2-communications/"}
        ],
        "resources": ["Phishery GitHub", "DarkHydrus attack flow analysis", "Cobalt Strike and RogueRobin usage examples"],
        "remediation": "Block execution of IQY files and disable external template loading in Microsoft Office. Train users to recognize spearphishing attempts involving password-protected archives and macro-enabled documents.",
        "improvements": "Deploy alerting on abnormal PowerShell executions with hidden window styles. Detect template injection by analyzing remote template requests from Office documents.",
        "hunt_steps": [
            "Search for execution of PowerShell with `-WindowStyle Hidden`.",
            "Identify .iqy or .docx files pulling templates from remote URLs.",
            "Detect use of open-source tools like Phishery, Empire, or Cobalt Strike within the environment.",
            "Monitor for forced authentication attempts via unexpected template loads."
        ],
        "expected_outcomes": [
            "Detection of PowerShell-based lateral movement and payload download.",
            "Identification of remote template loading linked to credential harvesting.",
            "Uncovering use of known open-source offensive tools like Mimikatz and RogueRobin."
        ],
        "false_positive": "PowerShell hidden windows can occur in legitimate automation. Use command line arguments and parent process lineage to differentiate.",
        "clearing_steps": [
            "Block Office applications from executing macros or remote templates by policy.",
            "Clean malicious .iqy, .docx, and script files from affected endpoints.",
            "Revoke compromised credentials harvested via forced authentication techniques.",
            "Audit tool usage (e.g., Cobalt Strike) for beaconing activity or persistence mechanisms."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
