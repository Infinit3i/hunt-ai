def get_content():
    return {
        "id": "G0071",
        "url_id": "Orangeworm",
        "title": "Orangeworm",
        "tags": ["healthcare", "corporate-espionage", "Kwampirs", "Shamoon-link", "United States", "Europe", "Asia"],
        "description": (
            "Orangeworm is a threat group that has been active since at least 2015, primarily targeting healthcare organizations in the United States, Europe, and Asia. "
            "Its primary tool, Kwampirs, is a backdoor that enables persistence and data gathering. "
            "The group appears to be focused on corporate espionage. Reverse engineering has revealed code and functional overlaps with Shamoon, suggesting possible links or shared development resources."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1071.001",  # HTTP (C2)
            "T1021.002"   # Remote Services: SMB/Windows Admin Shares
        ],
        "contributors": ["Elger Vinicius S. Rodrigues", "@elgervinicius", "CYBINT Centre"],
        "version": "2.0",
        "created": "17 October 2018",
        "last_modified": "10 April 2024",
        "navigator": "",
        "references": [
            {"source": "Symantec", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/orangeworm-healthcare"},
            {"source": "Pablo Rincón Crespo", "url": "https://cyberintel.es/research/kwampirs-shamoon-link-2022"},
            {"source": "Symantec Indicators", "url": "https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/orangeworm-iocs"}
        ],
        "resources": [],
        "remediation": (
            "Segment healthcare networks and isolate legacy systems from public-facing infrastructure. "
            "Restrict SMB share access and enforce strict file access controls. "
            "Monitor for Kwampirs signatures and SMB lateral movement behavior."
        ),
        "improvements": (
            "Enable logging and alerting for remote access to administrative shares (e.g., ADMIN$, C$). "
            "Apply application control to restrict execution of unknown binaries. "
            "Deploy EDR with heuristics capable of detecting Kwampirs variants and masquerading behavior."
        ),
        "hunt_steps": [
            "Look for unusual use of rundll32 launching unknown payloads.",
            "Scan SMB logs for unauthorized remote file copies to ADMIN$, C$, D$, and E$ shares.",
            "Check for signs of Kwampirs or tools executing with file padding or obfuscated payloads."
        ],
        "expected_outcomes": [
            "Detection of unauthorized SMB share access and backdoor deployment.",
            "Identification of machines hosting or receiving Kwampirs-like binaries.",
            "Mapping of lateral movement paths across healthcare or industrial networks."
        ],
        "false_positive": (
            "Use of rundll32.exe or SMB shares may be legitimate in certain administrative tasks. "
            "Confirm anomalies by correlating with time-of-day patterns, user activity, and endpoint telemetry."
        ),
        "clearing_steps": [
            "Delete all Kwampirs-related files and binaries from compromised systems.",
            "Revoke compromised domain or local accounts if observed in lateral movement.",
            "Patch systems to remove any exposed SMB-related vulnerabilities."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
