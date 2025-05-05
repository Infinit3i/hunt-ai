def get_content():
    return {
        "id": "G0019",
        "url_id": "Naikon",
        "title": "Naikon",
        "tags": ["state-sponsored", "espionage", "PLA", "Southeast-Asia", "China"],
        "description": (
            "Naikon is a state-sponsored cyber espionage group attributed to the Chinese People’s Liberation Army’s (PLA) Chengdu Military Region "
            "Second Technical Reconnaissance Bureau (Military Unit Cover Designator 78020). Active since at least 2010, Naikon has primarily targeted "
            "government, military, and civil organizations in Southeast Asia, as well as international bodies such as the UNDP and ASEAN. While it shares "
            "some operational traits with APT30, it is considered a distinct group."
        ),
        "associated_groups": [],
        "campaigns": [],
        "techniques": [
            "T1547.001", "T1574.001", "T1036.004", "T1036.005", "T1046", "T1137.006", "T1566.001", "T1018", "T1053.005",
            "T1518.001", "T1016", "T1204.002", "T1078.002", "T1047"
        ],
        "contributors": ["Kyaw Pyiyt Htet (@KyawPyiytHtet)"],
        "version": "2.0",
        "created": "31 May 2017",
        "last_modified": "16 April 2025",
        "navigator": "",
        "references": [
            {"source": "ThreatConnect Inc. and DGI", "url": "https://www.threatconnect.com/blog/project-camerashy/"},
            {"source": "Kaspersky - MsnMM Campaigns", "url": "https://securelist.com/msnmm-campaigns-naikon/"},
            {"source": "Kaspersky - Naikon APT", "url": "https://securelist.com/the-naikon-apt/"},
            {"source": "Vrabie, V. (Bitdefender)", "url": "https://labs.bitdefender.com/2021/04/naikon-traces-from-a-military-cyber-espionage-operation/"},
            {"source": "Check Point Research", "url": "https://research.checkpoint.com/2020/naikon-apt-cyber-espionage-reloaded/"}
        ],
        "resources": [],
        "remediation": (
            "Implement behavioral monitoring to detect DLL side-loading, masquerading of tasks and services, and unauthorized scheduled tasks. "
            "Block execution of unsigned or untrusted macros and restrict access to registry startup keys where possible. "
            "Monitor for usage of administrative credentials and use of WMIC or schtasks in unusual contexts."
        ),
        "improvements": (
            "Harden endpoints by limiting local admin access and auditing scheduled task creation and registry changes. "
            "Deploy alerts for suspicious use of task names mimicking known binaries like 'taskmgr'."
        ),
        "hunt_steps": [
            "Identify services with suspicious names that mimic legitimate tools.",
            "Detect DLL side-loading patterns especially from non-standard paths.",
            "Look for Word startup folder abuse via `.wll` files.",
            "Trace usage of `schtasks.exe`, `wmic.exe`, and `netsh` commands across endpoints."
        ],
        "expected_outcomes": [
            "Detection of persistence mechanisms used by Naikon such as registry Run keys and scheduled tasks.",
            "Identification of lateral movement via administrator accounts and WMIC.",
            "Attribution of obfuscated payloads to Naikon malware families."
        ],
        "false_positive": (
            "Some administrative tools such as `schtasks` and `wmic` may be used legitimately in enterprise environments. "
            "Careful tuning and context-aware analysis is necessary to avoid alert fatigue."
        ),
        "clearing_steps": [
            "Remove malicious DLLs and `.wll` files from startup folders.",
            "Revoke compromised domain admin credentials.",
            "Audit and remove suspicious scheduled tasks and registry keys."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
