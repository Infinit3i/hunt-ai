def get_content():
    return {
        "id": "G0105",
        "url_id": "DarkVishnya",
        "title": "DarkVishnya",
        "tags": ["financial", "eastern-europe", "physical-access", "financially-motivated", "impacket", "bash-bunny"],
        "description": "DarkVishnya is a financially motivated threat group that targeted at least 8 financial institutions in Eastern Europe between 2017 and 2018. The group is notable for using physical devices like Bash Bunny, Raspberry Pi, and laptops physically connected to internal networks to gain access, and for leveraging tools like Impacket, PsExec, and Winexe.",
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1110", "T1059.001", "T1543.003", "T1200", "T1046", "T1135", "T1040",
            "T1571", "T1588.002", "T1219"
        ],
        "contributors": [],
        "version": "1.1",
        "created": "15 May 2020",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "Kaspersky", "url": "https://securelist.com/darkvishnya-attacks-on-banks/89114/"}
        ],
        "resources": ["Securelist: DarkVishnya attacks on banks"],
        "remediation": "Audit physical access controls at all facilities. Disable unused ports and monitor for unauthorized device connections. Enforce network segmentation and credential hygiene.",
        "improvements": "Deploy network intrusion detection systems to monitor for anomalous port usage and shellcode loaders. Monitor PowerShell execution with suspicious parameters.",
        "hunt_steps": [
            "Search for PowerShell scripts creating or loading shellcode.",
            "Scan for services using non-standard ports such as 5190, 7900, 4444, 4445, 31337.",
            "Review physical security logs and USB connection records for rogue devices.",
            "Look for the presence or execution of tools like PsExec, Winexe, or Impacket."
        ],
        "expected_outcomes": [
            "Identification of unauthorized access via physical devices.",
            "Detection of non-standard port listeners for shellcode.",
            "Uncovering lateral movement via remote control tools like DameWare or PsExec."
        ],
        "false_positive": "Network scanning or port usage by security tools may resemble malicious activity. Contextualize with time, location, and user activity.",
        "clearing_steps": [
            "Disconnect and confiscate unauthorized hardware.",
            "Reset credentials potentially captured via sniffing.",
            "Clean shellcode loader services and associated payloads.",
            "Reinforce physical access controls and IT asset tracking."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
