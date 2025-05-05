def get_content():
    return {
        "id": "G0039",
        "url_id": "Suckfly",
        "title": "Suckfly",
        "tags": ["china-based", "credential theft", "code signing", "espionage"],
        "description": (
            "Suckfly is a China-based threat group that has been active since at least 2014. "
            "The group is known for its use of stolen code-signing certificates, credential dumping tools, "
            "and legitimate account abuse to conduct stealthy operations across internal networks, primarily "
            "targeting government and commercial sectors."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1059.003",  # Windows Command Shell
            "T1046",      # Network Service Discovery
            "T1003",      # OS Credential Dumping
            "T1553.002",  # Code Signing
            "T1078"       # Valid Accounts
        ],
        "contributors": [],
        "version": "1.1",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "DiMaggio, J. (Symantec)",
                "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/suckfly-code-signing"
            },
            {
                "source": "DiMaggio, J. (Symantec)",
                "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/suckfly-india-targets"
            }
        ],
        "resources": [],
        "remediation": (
            "Revoke and reissue any certificates suspected of compromise. "
            "Deploy advanced credential protection and monitor for unusual use of valid accounts. "
            "Restrict use of administrative privileges and monitor command-line execution."
        ),
        "improvements": (
            "Implement strict code-signing policies and certificate monitoring. "
            "Enhance detection rules for command-line tooling and lateral movement. "
            "Use network segmentation to reduce internal reconnaissance effectiveness."
        ),
        "hunt_steps": [
            "Scan for tools executed via Windows Command Shell with high privilege.",
            "Inspect logs for reconnaissance of uncommon ports (e.g., 8080, 5900, 40).",
            "Review usage of valid accounts outside of expected hours or geographies.",
            "Audit certificates in use and verify against trusted root authorities."
        ],
        "expected_outcomes": [
            "Identification of malicious use of valid accounts.",
            "Detection of unauthorized credential dumping activity.",
            "Discovery of signed malware and internal network enumeration attempts."
        ],
        "false_positive": (
            "Legitimate administrative scripts may appear similar to command-line driven attacks. "
            "Verify context, frequency, and user roles to reduce noise."
        ),
        "clearing_steps": [
            "Disable compromised accounts and reset associated passwords.",
            "Remove malicious files signed with stolen certificates.",
            "Patch vulnerable systems and monitor for reinfection attempts."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
