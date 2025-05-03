def get_content():
    return {
        "id": "G0120",
        "url_id": "Evilnum",
        "title": "Evilnum",
        "tags": ["financially motivated", "Europe", "spearphishing", "JavaScript", "TeamViewer abuse"],
        "description": (
            "Evilnum is a financially motivated threat group that has been active since at least 2018. "
            "The group is known for using spearphishing emails, malicious JavaScript, and remote desktop tools like TeamViewer to target victims, primarily in the financial sector. "
            "Evilnum has deployed malware variants such as TerraTV and loaders like TerraLoader to evade detection and maintain persistent access to victim machines."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1548.002", "T1059.007", "T1555", "T1574.001", "T1070.004", "T1105", "T1566.002", "T1219.002",
            "T1539", "T1204.001", "T1497.001"
        ],
        "contributors": [],
        "version": "1.0",
        "created": "22 January 2021",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Porolli, M. (2020). More evil: A deep look at Evilnum and its toolset",
                "url": "https://example.com/more-evil-evilnum-analysis"
            },
            {
                "source": "Adamitis, D. (2020). Phantom in the Command Shell",
                "url": "https://example.com/phantom-command-shell"
            }
        ],
        "resources": [],
        "remediation": (
            "Restrict script-based execution in email clients and web browsers. Block untrusted .LNK and .ZIP file execution. "
            "Limit use of remote desktop software and require MFA for any external access mechanisms."
        ),
        "improvements": (
            "Enhance detection of JavaScript and shortcut-based download chains. Apply behavior-based detection for common tools abused by Evilnum, "
            "including TeamViewer and LaZagne. Track file deletion, timestomping, and registry key changes associated with persistence."
        ),
        "hunt_steps": [
            "Review downloads and executions of ZIP or LNK files sourced from Google Drive.",
            "Investigate suspicious rundll32 or regsvr32 activity tied to unknown DLLs in TeamViewer directories.",
            "Search for credential theft activity involving LaZagne or browser data harvesting tools.",
            "Monitor registry startup locations for indicators of EVILNUM persistence.",
            "Correlate remote desktop usage with anomalous login behavior."
        ],
        "expected_outcomes": [
            "Detection of phishing and JavaScript loader chains.",
            "Identification of credential exfiltration using tools like LaZagne.",
            "Exposure of unauthorized RDP usage via repackaged remote desktop utilities."
        ],
        "false_positive": (
            "Legitimate use of TeamViewer and PowerShell may overlap with some Evilnum techniques—context and behavioral chaining are essential for validation."
        ),
        "clearing_steps": [
            "Terminate active remote desktop sessions and remove any unauthorized RDP tools.",
            "Delete persistent registry entries and scheduled tasks created by the malware.",
            "Revoke compromised credentials and perform a system audit to remove residual tools and dropped DLLs."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
