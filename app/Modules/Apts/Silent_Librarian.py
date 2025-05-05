def get_content():
    return {
        "id": "G0122",
        "url_id": "Silent_Librarian",
        "title": "Silent Librarian",
        "tags": ["Iran", "Mabna Institute", "academia", "phishing", "credential theft", "research targeting"],
        "description": (
            "Silent Librarian is a threat actor group affiliated with the Iran-based Mabna Institute, believed to act on behalf of "
            "the Islamic Revolutionary Guard Corps (IRGC). Active since at least 2013, the group has targeted academic institutions, "
            "government agencies, and private sector entities globally, especially those involved in research and intellectual property. "
            "Their operations rely heavily on phishing campaigns, domain spoofing, and credential theft using realistic cloned login pages."
        ),
        "associated_groups": ["TA407", "COBALT DICKENS"],
        "campaigns": [],
        "techniques": [
            "T1583.001", "T1110.003", "T1114", "T1114.003", "T1585.002", "T1589.002", "T1589.003",
            "T1588.002", "T1588.004", "T1598.003", "T1594", "T1608.005", "T1078"
        ],
        "contributors": [],
        "version": "1.0",
        "created": "03 February 2021",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "DOJ", "url": "https://www.justice.gov/opa/pr/nine-iranians-charged-conducting-massive-cyber-theft-campaign-behalf-islamic-revolutionary"},
            {"source": "Malwarebytes", "url": "https://blog.malwarebytes.com/threat-analysis/2020/10/silent-librarian-apt-right-on-schedule-for-2020-2021-academic-year/"},
            {"source": "Proofpoint", "url": "https://www.proofpoint.com/us/threat-insight/post/threat-actor-profile-ta407-silent-librarian"},
            {"source": "SecureWorks", "url": "https://www.secureworks.com/blog/back-to-school-cobalt-dickens-targets-universities"},
            {"source": "SecureWorks", "url": "https://www.secureworks.com/blog/cobalt-dickens-goes-back-to-school-again"}
        ],
        "resources": [],
        "remediation": (
            "Implement multi-factor authentication (MFA) across email and academic portals. "
            "Educate users on phishing risks, including realistic clone sites. "
            "Block newly registered free TLD domains (e.g., .TK, .ML, .GA) at the network boundary."
        ),
        "improvements": (
            "Deploy email filtering systems capable of detecting spoofed domains and URL shorteners. "
            "Monitor for unauthorized email forwarding rules and anomalous logins from unusual IPs or geographies. "
            "Conduct frequent audits of DNS records and public-facing academic branding materials to detect misuse."
        ),
        "hunt_steps": [
            "Identify lookalike domain registrations targeting your organization or partner institutions.",
            "Search for auto-forwarding rules in user mailboxes that redirect to external accounts.",
            "Review external logins to OWA and cloud services during off-hours or from foreign regions."
        ],
        "expected_outcomes": [
            "Early detection of phishing infrastructure targeting academic staff or students.",
            "Blocking of credential harvesting attempts before sensitive data exfiltration.",
            "Removal of malicious forwarding rules and resetting of compromised accounts."
        ],
        "false_positive": "Freely available tools like HTTrack or SingleFile may be used for legitimate purposes; context and target indicators are essential.",
        "clearing_steps": [
            "Disable forwarding rules and invalidate tokens associated with compromised credentials.",
            "Re-image affected systems if phishing site payloads were downloaded.",
            "Conduct password resets and notify affected users for awareness and training."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": [
                "https://blog.malwarebytes.com/threat-analysis/2020/10/silent-librarian-apt-right-on-schedule-for-2020-2021-academic-year/",
                "https://www.secureworks.com/blog/cobalt-dickens-goes-back-to-school-again"
            ]
        }
    }
