def get_content():
    return {
        "id": "G0024",
        "url_id": "Putter_Panda",
        "title": "Putter Panda",
        "tags": ["china", "espionage", "unit61486", "PLA", "APT2"],
        "description": (
            "Putter Panda is a Chinese cyber espionage group associated with Unit 61486 of the 12th Bureau of the People’s Liberation Army "
            "(PLA) 3rd General Staff Department (GSD). The group has historically focused on targeting U.S. and European entities, especially those "
            "involved in satellite, aerospace, and communications industries. Their operations include use of customized malware, spearphishing, and exploitation of public-facing web servers."
        ),
        "associated_groups": ["APT2", "MSUpdater"],
        "campaigns": [],
        "techniques": [
            "T1547.001",  # Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
            "T1562.001",  # Impair Defenses: Disable or Modify Tools
            "T1027.013",  # Obfuscated Files or Information: Encrypted/Encoded File
            "T1055.001"   # Process Injection: Dynamic-link Library Injection
        ],
        "contributors": ["MITRE ATT&CK Team"],
        "version": "1.2",
        "created": "31 May 2017",
        "last_modified": "17 November 2024",
        "navigator": "",
        "references": [
            {
                "source": "CrowdStrike Global Intelligence Team",
                "url": "https://www.crowdstrike.com/blog/putter-panda/"
            },
            {
                "source": "Gross, J. and Walter, J.",
                "url": "https://unit42.paloaltonetworks.com/puttering-into-the-future/"
            }
        ],
        "resources": [],
        "remediation": (
            "Implement robust endpoint protection capable of detecting registry modifications and process injection behavior. "
            "Harden systems by disabling unnecessary services, monitoring for unusual process execution (e.g., msinm.exe or iexplore.exe), and "
            "restricting DLL injection capabilities through OS-level protections."
        ),
        "improvements": (
            "Improve visibility into registry key changes, especially under user-run persistence paths. Use behavior analytics to detect tools attempting to disable AV processes. "
            "Enhance incident response playbooks for dealing with DLL injection and encoded payloads."
        ),
        "hunt_steps": [
            "Search for suspicious persistence in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.",
            "Look for attempts to terminate processes associated with known AV products (e.g., SAVAdminService.exe).",
            "Hunt for DLL injection attempts into network-facing processes like browsers or email clients.",
            "Review encoded or encrypted payloads that use patterns consistent with RC4 or XOR obfuscation."
        ],
        "expected_outcomes": [
            "Detection of registry-based persistence mechanisms.",
            "Identification of process tampering to disable AV tools.",
            "Discovery of obfuscated or encrypted files dropped by Putter Panda.",
            "Evidence of malicious DLL injection into trusted applications."
        ],
        "false_positive": (
            "Some registry keys under HKCU\\...\\Run are used legitimately by user-installed software. Cross-reference with software inventory "
            "and analyze binary origin and behavior before acting."
        ),
        "clearing_steps": [
            "Remove unauthorized registry keys used for persistence.",
            "Kill injected processes and terminate suspicious DLLs.",
            "Re-enable any disabled AV components and conduct a full system scan.",
            "Remove any dropped payloads and reimage systems if compromise is deep or uncertain."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
