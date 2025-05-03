def get_content():
    return {
        "id": "G0137",
        "url_id": "Ferocious_Kitten",
        "title": "Ferocious Kitten",
        "tags": ["surveillance", "Iran", "Persian-speaking targets", "APT", "spearphishing"],
        "description": (
            "Ferocious Kitten is a threat group that has been active since at least 2015, "
            "primarily targeting Persian-speaking individuals in Iran. The group is known for "
            "conducting long-term surveillance operations and using custom malware like MarkiRAT. "
            "Their tactics include spearphishing with decoy documents, masquerading techniques such "
            "as right-to-left override, and use of legitimate tools and infrastructure to maintain stealth."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1583.001", "T1036.002", "T1036.005", "T1588.002", "T1566.001", "T1204.002"
        ],
        "contributors": [
            "Pooja Natarajan, NEC Corporation India",
            "Manikantan Srinivasan, NEC Corporation India",
            "Hiroki Nagahama, NEC Corporation"
        ],
        "version": "1.0",
        "created": "28 September 2021",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "GReAT (2021). Ferocious Kitten: 6 Years of Covert Surveillance in Iran",
                "url": "https://example.com/ferocious-kitten-surveillance"
            }
        ],
        "resources": [],
        "remediation": (
            "Implement attachment sandboxing and disable macro content in documents from untrusted sources. "
            "Deploy email authentication methods (SPF/DKIM/DMARC) and monitor for RLO unicode characters in filenames."
        ),
        "improvements": (
            "Enhance endpoint visibility for script execution and registry changes. Monitor for the presence of open-source tools "
            "such as Psiphon and behavior consistent with MarkiRAT, including clipboard access, keystroke logging, and screen capture activity."
        ),
        "hunt_steps": [
            "Identify suspicious file names with right-to-left override unicode characters.",
            "Detect processes named 'update.exe' running from user-accessible locations like the Public folder.",
            "Monitor BITS job creation used for file transfer outside normal application behavior.",
            "Look for signs of clipboard monitoring and screen capture on non-admin user accounts."
        ],
        "expected_outcomes": [
            "Detection of spearphishing attachment attempts leveraging decoy messaging.",
            "Identification of RLO-based masquerading used to disguise executable payloads.",
            "Recognition of persistent malware with surveillance capabilities on target endpoints."
        ],
        "false_positive": (
            "Use of update.exe and BITS jobs can be legitimate; correlation with spearphishing emails and unusual user behavior is necessary."
        ),
        "clearing_steps": [
            "Terminate and remove MarkiRAT and related artifacts from the infected system.",
            "Reset credentials and monitor for continued clipboard, keystroke, or screen capture activity.",
            "Delete malicious scheduled tasks and registry run entries used for persistence."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
