def get_content():
    return {
        "id": "G0034",
        "url_id": "Sandworm_Team",
        "title": "Sandworm Team",
        "tags": ["russia", "grunit74455", "notpetya", "olympic-destroyer", "ukraine", "ics", "destructive-malware", "apt44"],
        "description": (
            "Sandworm Team is a destructive threat actor attributed to Russia's GRU Unit 74455, active since at least 2009. The group is known for a wide range of high-profile cyber operations including the 2015 and 2016 Ukraine electric power attacks, the 2017 NotPetya malware outbreak, and the 2018 Olympic Destroyer incident. They have targeted critical infrastructure, governmental, and private sector entities using a mix of spearphishing, supply chain attacks, malware deployment, and sophisticated OT-level techniques."
        ),
        "associated_groups": ["ELECTRUM", "Telebots", "IRON VIKING", "BlackEnergy (Group)", "Quedagh", "Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "FROZENBARENTS", "APT44"],
        "campaigns": ["2015 Ukraine Electric Power Attack", "2016 Ukraine Electric Power Attack", "2022 Ukraine Electric Power Attack"],
        "techniques": [
            "T1059.001", "T1059.003", "T1059.005", "T1136.002", "T1543.003", "T1485", "T1486", "T1203", "T1561.002", "T1484.001", "T1499", "T1566.001", "T1566.002", "T1218.011", "T1082", "T1027", "T1027.002", "T1055", "T1041", "T1204.002", "T1021.002", "T1105", "T1070.004", "T1106", "T1583.001", "T1587.001", "T1588.002", "T1588.006", "T1003.001", "T1003.003", "T1591.002", "T1592.002", "T1593", "T1594", "T1190", "T1195.002"
        ],
        "contributors": ["Dragos Threat Intelligence", "Hakan KARABACAK"],
        "version": "4.2",
        "created": "31 May 2017",
        "last_modified": "04 December 2024",
        "navigator": "",
        "references": [
            {"source": "DOJ Indictment 2020", "url": "https://www.justice.gov/opa/press-release/file/1328521/download"},
            {"source": "UK NCSC Advisory", "url": "https://www.ncsc.gov.uk/news/gru-cyber-attacks"},
            {"source": "Booz Allen Hamilton Ukraine Report", "url": "https://www.boozallen.com/sandworm"}
        ],
        "resources": [],
        "remediation": (
            "Segment OT and IT networks, implement allow-listing, monitor Group Policy changes, restrict macro execution, and enhance backup strategies with offline and immutable backups. Apply defense-in-depth practices across endpoints and network layers."
        ),
        "improvements": (
            "Adopt secure software development practices to prevent supply chain abuse, ensure rigorous monitoring of domain creation activities, enforce anomaly detection on OT networks, and develop incident playbooks for ICS-level compromise."
        ),
        "hunt_steps": [
            "Audit systems for unauthorized service creation and Group Policy changes.",
            "Search for evidence of PowerShell and VBScript abuse, particularly in combination with rundll32.exe or scilc.exe.",
            "Detect lateral movement via Admin$ shares and SMB-related artifacts.",
            "Review scheduled tasks created via GPO or unexpected VBS scripts.",
            "Check registry entries for persistence mechanisms or altered Internet security zones."
        ],
        "expected_outcomes": [
            "Detection of destructive malware pre-execution.",
            "Early indicators of credential harvesting and lateral movement.",
            "Forensics-based identification of command-and-control infrastructures and tunneling activities."
        ],
        "false_positive": (
            "Use of scheduled tasks, SMB shares, and PowerShell may be common in enterprise environments. Correlate with context, timing, and known IOC behavior."
        ),
        "clearing_steps": [
            "Terminate malicious services and scheduled tasks.",
            "Restore GPO to baseline.",
            "Isolate affected ICS/SCADA systems and recover from known-good backups.",
            "Revoke compromised credentials and monitor for post-wipe persistence."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
