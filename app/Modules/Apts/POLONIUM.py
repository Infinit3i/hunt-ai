def get_content():
    return {
        "id": "G1005",
        "url_id": "POLONIUM",
        "title": "POLONIUM",
        "tags": [
            "Lebanon", "Iran MOIS", "OneDrive", "DropBox", "espionage", "Middle East",
            "CreepyDrive", "CreepySnail", "cloud exfiltration", "2022+"
        ],
        "description": (
            "POLONIUM is a Lebanon-based threat group active since at least February 2022, "
            "notably targeting Israeli entities in sectors such as critical manufacturing, IT, and defense. "
            "The group leverages cloud services like Microsoft OneDrive and Dropbox for both command-and-control "
            "and exfiltration. It has coordinated activity and infrastructure overlap with actors linked to Iran’s "
            "Ministry of Intelligence and Security (MOIS), suggesting collaboration or shared tooling. POLONIUM "
            "has employed tools like AirVPN and plink, and used compromised credentials to pivot into multiple environments."
        ),
        "associated_groups": ["Plaid Rain"],
        "campaigns": [],
        "techniques": [
            "T1583.006", "T1567.002", "T1588.002", "T1090", "T1199", "T1078", "T1102.002"
        ],
        "contributors": ["Microsoft Threat Intelligence"],
        "version": "2.0",
        "created": "01 July 2022",
        "last_modified": "08 January 2024",
        "navigator": "",
        "references": [
            {
                "source": "Microsoft - Exposing POLONIUM",
                "url": "https://www.microsoft.com/security/blog/2022/06/02/exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/"
            },
            {
                "source": "Microsoft - Naming Threat Actors",
                "url": "https://www.microsoft.com/en-us/security/blog/2023/07/12/how-microsoft-names-threat-actors/"
            }
        ],
        "resources": [],
        "remediation": (
            "Monitor for unusual use of OneDrive or Dropbox in enterprise environments. "
            "Implement strict access controls and auditing for third-party cloud storage. "
            "Investigate any use of remote proxy tools like AirVPN and plink. "
            "Ensure that trusted third parties do not become a vector for downstream compromise."
        ),
        "improvements": (
            "Deploy cloud application security brokers (CASBs) to track and control data exfiltration via SaaS tools. "
            "Enforce MFA and conditional access on accounts with cloud access. "
            "Detect anomalous authentication events, especially those from proxy/VPN sources such as AirVPN."
        ),
        "hunt_steps": [
            "Detect PowerShell scripts interacting with OneDrive or Dropbox APIs.",
            "Look for outbound traffic to cloud storage domains outside business hours or policy.",
            "Search for AirVPN or plink binary executions in user directories.",
            "Hunt for access tokens or credentials being reused across lateral movements."
        ],
        "expected_outcomes": [
            "Identification of stealthy data exfiltration via OneDrive or Dropbox.",
            "Detection of third-party remote access abuse or credential compromise.",
            "Uncovering of operational coordination between POLONIUM and Iranian-affiliated groups."
        ],
        "false_positive": (
            "Legitimate use of cloud storage services may resemble POLONIUM TTPs. "
            "Ensure context (e.g., data types, destinations, accounts involved) is validated."
        ),
        "clearing_steps": [
            "Revoke all application access tokens tied to OneDrive and Dropbox.",
            "Block VPN/proxy tools like AirVPN and terminate corresponding sessions.",
            "Audit and reset credentials across all affected environments.",
            "Purge implanted tools such as CreepyDrive and CreepySnail from endpoints."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
