def get_content():
    return {
        "id": "G1019",
        "url_id": "MoustachedBouncer",
        "title": "MoustachedBouncer",
        "tags": ["espionage", "belarus", "diplomatic targets", "content injection", "custom malware"],
        "description": (
            "MoustachedBouncer is a cyberespionage group active since at least 2014 that targets foreign embassies in Belarus. "
            "The group is known for advanced techniques such as DNS/HTTP/SMB content injection, the use of custom malware plugins, "
            "and masquerading its payloads as legitimate Windows updates. It leverages privilege escalation exploits, remote staging, "
            "and advanced evasion methods to remain undetected during operations."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1059.001", "T1059.007", "T1659", "T1074.002", "T1068",
            "T1027.002", "T1090", "T1113", "T1655.001"
        ],
        "contributors": [],
        "version": "1.0",
        "created": "25 September 2023",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {
                "source": "Faou, M.",
                "url": "https://www.welivesecurity.com/en/eset-research/moustachedbouncer-espionage-against-foreign-diplomats-in-belarus/"
            }
        ],
        "resources": [],
        "remediation": (
            "Segment embassy networks from untrusted infrastructure, enforce application whitelisting, and inspect DNS/HTTP "
            "replies for tampering. Update all hosts with mitigations for CVE-2021-1732 and related privilege escalation vectors."
        ),
        "improvements": (
            "Deploy deep packet inspection and security tools capable of detecting SMB/HTTP response manipulation. "
            "Harden network boundaries, and log PowerShell/JavaScript usage with script block logging enabled."
        ),
        "hunt_steps": [
            "Search for unusual PowerShell and JavaScript activity associated with unknown HTML payloads.",
            "Scan SMB shares (e.g., `\\.\AActdata\\`) for staged screenshot files or unauthorized storage.",
            "Detect Themida-packed executables or those matching legitimate filenames like 'MicrosoftUpdate845255.exe'."
        ],
        "expected_outcomes": [
            "Detection of fake Windows Update redirection via content injection.",
            "Discovery of custom malware like Disco, SharpDisco, or NightClub.",
            "Identification of persistent screen capture or keylogging activity using embedded plugins."
        ],
        "false_positive": (
            "Legitimate use of tools with obfuscation or scripting (e.g., PowerShell) may appear similar. "
            "Ensure behavioral correlation and verify execution context before escalation."
        ),
        "clearing_steps": [
            "Terminate processes tied to obfuscated or masquerading binaries.",
            "Remove malware plugins and clear related scheduled tasks or services.",
            "Audit DNS/HTTP infrastructure for signs of manipulation or redirection proxies."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
