def get_content():
    return {
        "id": "G0051",
        "url_id": "FIN10",
        "title": "FIN10",
        "tags": ["financially motivated", "extortion", "North America", "PowerShell Empire", "lateral movement", "scheduled task"],
        "description": (
            "FIN10 is a financially motivated threat group that targeted organizations in North America from at least 2013 to 2016. "
            "They have used stolen data for extortion and leveraged tools like PowerShell Empire and Meterpreter for persistence, "
            "lateral movement, and data exfiltration. FIN10's operations show extensive use of legitimate credentials, batch scripts, "
            "RDP, and scheduled tasks to maintain access and evade detection."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1547.001", "T1059.001", "T1059.003", "T1070.004", "T1570", "T1588.002", "T1021.001",
            "T1053.005", "T1033", "T1078", "T1078.003"
        ],
        "contributors": [],
        "version": "1.3",
        "created": "14 December 2017",
        "last_modified": "17 November 2024",
        "navigator": "",
        "references": [
            {
                "source": "FireEye iSIGHT Intelligence",
                "url": "https://www.fireeye.com/blog/threat-research/2017/06/fin10-anatomy-of-a-cyber-extortion-operation.html"
            },
            {
                "source": "GitHub PowerShellEmpire",
                "url": "https://github.com/EmpireProject/Empire"
            }
        ],
        "resources": [],
        "remediation": (
            "Disable PowerShell where not needed and monitor for Empire-specific patterns. Enforce strong multi-factor authentication "
            "on VPN access and remote services. Audit scheduled tasks for unusual configurations, especially those with SYSTEM privileges."
        ),
        "improvements": (
            "Deploy behavioral monitoring to detect lateral movement via RDP and local account re-use. Apply endpoint protection "
            "capable of identifying Meterpreter and SplinterRAT payloads. Correlate registry run key modifications with user actions."
        ),
        "hunt_steps": [
            "Search for registry modifications under Run/RunOnce keys created by PowerShell Empire.",
            "Identify use of scheduled tasks referencing encoded PowerShell commands.",
            "Analyze VPN authentication logs for suspicious single-factor access with compromised credentials.",
            "Detect .bat scripts that include PowerShell or system file deletion logic."
        ],
        "expected_outcomes": [
            "Detection of persistence mechanisms such as S4U scheduled tasks or Run key entries.",
            "Identification of lateral movement behavior using RDP with local administrator credentials.",
            "Recovery of forensic evidence indicating use of open-source frameworks like Empire."
        ],
        "false_positive": (
            "Use of scheduled tasks and PowerShell is common in enterprise environments. Focus on encoded command usage, "
            "PowerShell Empire indicators, and anomalous timing of task creation."
        ),
        "clearing_steps": [
            "Terminate Empire agent sessions and remove associated persistence (Run keys, scheduled tasks).",
            "Revoke compromised accounts and reset all local administrator credentials.",
            "Delete malicious batch scripts and tool payloads (Meterpreter, SplinterRAT) from all infected hosts."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
