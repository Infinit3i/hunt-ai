def get_content():
    return {
        "id": "G0048",
        "url_id": "RTM",
        "title": "RTM",
        "tags": ["banking-trojan", "cybercrime", "russia", "remote-access", "financial-targeting"],
        "description": (
            "RTM (Read The Manual) is a financially motivated cybercriminal group active since at least 2015. "
            "It primarily targets remote banking systems in Russia and neighboring countries. RTM uses malware of the same name (RTM Trojan) to conduct espionage, credential theft, and unauthorized remote access. "
            "Distribution vectors include drive-by downloads using exploit kits, phishing attachments, and abuse of legitimate services like LiveJournal RSS feeds as dead drop resolvers. "
            "The group is known for modifying legitimate tools such as TeamViewer to maintain stealthy persistence and control over victim machines."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1547.001",  # Registry Run Keys / Startup Folder
            "T1189",      # Drive-by Compromise
            "T1574.001",  # DLL Search Order Hijacking
            "T1566.001",  # Spearphishing Attachment
            "T1219.002",  # Remote Desktop Software
            "T1204.002",  # Malicious File Execution
            "T1102.001"   # Dead Drop Resolver via Web Service
        ],
        "contributors": ["Oleg Skulkin, Group-IB"],
        "version": "1.1",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "ESET Research",
                "url": "https://www.welivesecurity.com/2017/02/28/rtm-banking-trojan-guide/"
            },
            {
                "source": "Group-IB - Skulkin, O.",
                "url": "https://www.group-ib.com/blog/rtm-trojan-forensics/"
            },
            {
                "source": "ESET Research (2019)",
                "url": "https://www.welivesecurity.com/2019/04/30/buhtrap-buran-distribution-rig/"
            }
        ],
        "resources": [],
        "remediation": (
            "Update all systems to mitigate exploit kit vulnerabilities. Disable unused scripting languages (e.g., VBScript) and block outbound connections to known malicious RSS feeds. "
            "Harden application execution policies and monitor registry keys and system paths for unauthorized autostart entries. Implement strict application control to detect modified remote access tools."
        ),
        "improvements": (
            "Deploy behavior-based detection for DLL search order hijacking and TeamViewer misuse. Monitor LiveJournal and other unusual RSS sources in outbound traffic. "
            "Use threat intelligence to enrich IOC correlation with exploit kits and financial malware families targeting regional banking sectors."
        ),
        "hunt_steps": [
            "Look for registry entries under HKCU\\...\\Run and associated persistence via TeamViewer.",
            "Inspect DLL paths and loaded modules for hijacked binaries.",
            "Monitor use of Rundll32 and its command-line parameters for abnormal behaviors.",
            "Analyze LiveJournal and similar web services in proxy logs for use as dead drop resolvers.",
            "Review scheduled tasks, clipboard access, screen capture, and keylogging behaviors.",
            "Search for signs of the RTM Trojan using behavioral indicators or hashes."
        ],
        "expected_outcomes": [
            "Detection of persistence mechanisms tied to modified TeamViewer instances.",
            "Identification of banking trojan activities like credential theft, clipboard monitoring, and remote access.",
            "Awareness of infection vectors using exploit kits and malicious attachments.",
            "Attribution of LiveJournal RSS traffic to malicious C2 infrastructure."
        ],
        "false_positive": (
            "Remote desktop tools like TeamViewer may be used legitimately. Carefully inspect file hashes, installation context, and behavior before concluding malicious use."
        ),
        "clearing_steps": [
            "Remove registry keys related to RTM and delete any unauthorized DLLs or modified binaries.",
            "Terminate unauthorized TeamViewer or Remote Utilities sessions.",
            "Flush DNS cache and remove saved credentials.",
            "Audit financial access logs and reset compromised user accounts."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
