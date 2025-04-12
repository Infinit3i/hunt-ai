def get_content():
    return {
        "id": "T1553.006",
        "url_id": "T1553/006",
        "title": "Subvert Trust Controls: Code Signing Policy Modification",
        "description": "Adversaries may modify code signing policies to allow the execution of unsigned or self-signed code. These policies are typically used to ensure only trusted, signed software runs, enforced through mechanisms such as Driver Signature Enforcement (DSE) on Windows or System Integrity Protection (SIP) on macOS. By altering settings or leveraging vulnerable drivers, adversaries can weaken or disable these protections.",
        "tags": ["Code Signing Policy", "DSE Bypass", "SIP Bypass", "Defense Evasion", "macOS", "Windows"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows, macOS",
        "tips": [
            "Monitor use of TESTSIGNING or csrutil disable commands.",
            "Audit driver signature settings in registry or NVRAM.",
            "Flag changes to g_CiOptions or relevant SIP/DSE variables.",
            "Correlate with exploitation of vulnerable signed drivers."
        ],
        "data_sources": "Command: Command Execution, Process: Process Creation, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Windows Registry", "location": "HKCU\\Software\\Policies\\Microsoft\\Windows NT\\Driver Signing", "identify": "Driver signing enforcement settings"},
            {"type": "Command", "location": "", "identify": "TESTSIGNING ON / csrutil disable"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Command-line monitoring for bcdedit or csrutil",
            "Registry key auditing for signing policies",
            "Memory analysis of g_CiOptions and SIP kernel flags",
            "Kernel-level integrity check enforcement"
        ],
        "apt": [
            "APT39",
            "Iron Tiger",
            "Turla",
            "AcidBox",
            "BlackEnergy"
        ],
        "spl_query": [
            "index=windows_logs process_name=bcdedit.exe OR process_name=csrutil\n| search command_line=*TESTSIGNING* OR *disable*"
        ],
        "hunt_steps": [
            "Search for recent use of TESTSIGNING or csrutil commands.",
            "Validate driver loading behavior and flag unsigned drivers.",
            "Scan for kernel memory artifacts related to signature enforcement."
        ],
        "expected_outcomes": [
            "Systems in test or insecure signing mode",
            "Unsigned drivers or code executing without restriction"
        ],
        "false_positive": "Developers may use TESTSIGNING or disable SIP for legitimate testing. Validate against purpose, timing, and role of affected system.",
        "clearing_steps": [
            "Run 'bcdedit /set TESTSIGNING OFF' on Windows.",
            "Use 'csrutil enable' from macOS Recovery.",
            "Reboot system to re-enable code integrity enforcement."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1112", "example": "Modify Registry to change signing policy."},
            {"tactic": "Privilege Escalation", "technique": "T1068", "example": "Exploit vulnerable driver to write to kernel memory."}
        ],
        "watchlist": [
            "TESTSIGNING enabled",
            "csrutil status shows SIP disabled",
            "Driver Signature Enforcement bypass techniques"
        ],
        "enhancements": [
            "Alert on boot in TESTSIGNING mode",
            "Integrate SIP status checks into macOS health monitoring"
        ],
        "summary": "By modifying code signing policies, adversaries disable OS-level integrity enforcement mechanisms and enable the execution of untrusted binaries. These changes may be done through registry keys, kernel memory, or developer tools.",
        "remediation": "Re-enable enforcement policies and monitor for any recurrence of insecure configurations. Conduct full EDR sweep of affected endpoints.",
        "improvements": "Automate policy status reporting across enterprise endpoints. Correlate policy changes with driver installation and privilege escalation paths.",
        "mitre_version": "16.1"
    }