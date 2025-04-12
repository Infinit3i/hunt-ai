def get_content():
    return {
        "id": "T1553.003",
        "url_id": "T1553/003",
        "title": "Subvert Trust Controls: SIP and Trust Provider Hijacking",
        "description": "Adversaries may tamper with SIP and trust provider components to mislead the operating system and application control tools when conducting signature validation checks. SIPs (Subject Interface Packages) and trust providers form a critical part of the digital signature verification pipeline in Windows, and manipulation of these components can allow unsigned or malicious code to appear trusted.",
        "tags": ["Windows", "SIP Hijacking", "Trust Provider", "Defense Evasion", "Registry Manipulation"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Periodically baseline SIPs and trust provider Registry entries.",
            "Enable CryptoAPI (CAPI) and Code Integrity event logging.",
            "Use Sysmon and Global Object Access Auditing for registry monitoring.",
            "Audit Autoruns entries with Microsoft and Windows filters turned off."
        ],
        "data_sources": "File: File Modification, Module: Module Load, Windows Registry: Windows Registry Key Modification",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""},
            {"type": "Module", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [],
        "destination_artifacts": [],
        "detection_methods": [
            "Registry key auditing and change detection",
            "Sysmon Event ID 3033 for Code Integrity violations",
            "CryptoAPI v2 (CAPI) logging analysis",
            "Autoruns anomalies identification"
        ],
        "apt": [
            "SpecterOps"
        ],
        "spl_query": [
            "index=windows_logs EventCode=3033 OR EventCode=81\n| search message=*trust provider* OR *SIP*"
        ],
        "hunt_steps": [
            "Review registry paths related to SIPs and Trust Providers for anomalies.",
            "Inspect loaded DLLs responsible for validation components.",
            "Audit newly introduced modules handling signature verification."
        ],
        "expected_outcomes": [
            "Detection of DLL hijacking attempts on trust validation components",
            "Identification of registry manipulation tied to SIP or trust behavior"
        ],
        "false_positive": "Some legitimate security tools may register custom trust providers or SIPs. These should be verified against internal baselines and vendor documentation.",
        "clearing_steps": [
            "Restore original DLL and registry paths for SIP and trust providers.",
            "Remove unauthorized or unknown DLLs and verify trust settings.",
            "Run SFC /SCANNOW and DISM for system integrity repair."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1574.001", "example": "DLL Search Order Hijacking of trust provider DLLs."},
            {"tactic": "Defense Evasion", "technique": "T1218.010", "example": "Regsvr32 used to register hijacked DLLs."}
        ],
        "watchlist": [
            "Registry edits to Cryptography\OID paths",
            "DLL loads in signature verification contexts",
            "Event ID 81 and 3033 anomalies"
        ],
        "enhancements": [
            "Implement alerting on modification of SIP and trust provider keys.",
            "Track exported function mismatches in DLLs responsible for validation"
        ],
        "summary": "SIP and trust provider hijacking targets the architecture Windows uses for code signing and signature verification. By manipulating registry paths or DLLs, adversaries can subvert trust controls and enable persistent evasion.",
        "remediation": "Reinforce integrity checks, monitor registry changes, and validate the integrity of all DLLs involved in signature processing.",
        "improvements": "Automate auditing of Cryptography keys and CAPI logs. Integrate endpoint behavior analytics tied to trust validation pathways.",
        "mitre_version": "16.1"
    }
