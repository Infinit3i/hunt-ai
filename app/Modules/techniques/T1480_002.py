def get_content():
    return {
        "id": "T1480.001",
        "url_id": "T1480/001",
        "title": "Execution Guardrails: Environmental Keying",
        "description": "Adversaries may environmentally key payloads or other features of malware to evade defenses and constrain execution to a specific target environment. Environmental keying uses cryptography to constrain execution or actions based on adversary supplied environment specific conditions that are expected to be present on the target. This can help protect adversary tactics, techniques, and procedures (TTPs) by making reverse engineering and static analysis more difficult.",
        "tags": ["environmental keying", "execution guardrails", "encrypted payload", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Look for suspicious processes that gather host-based or network-based system information.",
            "Correlate encrypted payloads with host environment analysis scripts.",
            "Alert on malware that aborts execution without expected system values."
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "binary or script", "location": "varies", "identify": "uses system variables as keys"},
            {"type": "memory dump", "location": "volatile", "identify": "decrypted payload post-fingerprint"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Look for processes using hardware, domain, or IP-based values prior to execution",
            "Analyze malware samples for decryption routines relying on system values",
            "Monitor processes exiting on unexpected system states"
        ],
        "apt": [
            "Pikabot", "Gauss", "InvisiMole", "Actinium", "APT41", "ToddyCat", "Winnti", "InkySquid"
        ],
        "spl_query": [
            "index=sysmon_logs ImageLoaded=*systeminfo* OR *ipconfig* OR *netstat* OR *whoami*\n| stats count by ParentImage, Image, CommandLine",
            "index=security_logs CommandLine=*hostname* OR *nltest* OR *wmic*\n| stats count by ParentImage, CommandLine, User"
        ],
        "hunt_steps": [
            "Search for scripts/binaries performing environment checks before decryption",
            "Trace malware samples that abort execution without certain conditions met",
            "Review files that decrypt or extract themselves only after fingerprint match"
        ],
        "expected_outcomes": [
            "Find malware requiring domain, device, or host info for activation",
            "Discover use of cryptographic functions tied to system environment",
            "Reveal attacker logic for controlled target exploitation"
        ],
        "false_positive": "Some legitimate software uses environment-specific licensing or protections. Focus on stealthy patterns and embedded cryptographic guards outside of setup routines.",
        "clearing_steps": [
            "Capture and analyze host-specific environment keys",
            "Rebuild or isolate systems showing payload decryption upon matching conditions",
            "Monitor for lateral movement tools with environmental locks"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1480.001", "example": "Payload decrypts only if hostname matches XYZ"},
            {"tactic": "Discovery", "technique": "T1082", "example": "Check local system fingerprint for execution decision"}
        ],
        "watchlist": [
            "Executables failing silently without specific domain or IP",
            "Processes collecting system details before payload decryption",
            "Binaries that show anti-analysis features tied to cryptographic checks"
        ],
        "enhancements": [
            "Integrate dynamic analysis for fingerprint-dependent malware",
            "Correlate early environment checks with successful payload runs",
            "Monitor registry, domain, and user profile values tied to malware triggers"
        ],
        "summary": "Environmental keying is a specialized form of execution guardrails that uses cryptographic constraints to ensure payloads only run on intended targets. This improves stealth and evasion by requiring target-specific values for decryption.",
        "remediation": "Isolate systems and reverse engineer fingerprinting logic to bypass or neutralize decryption keys. Capture volatile memory to analyze decrypted payloads post-execution.",
        "improvements": "Improve sandbox fidelity by emulating network, host, and domain conditions expected by guarded payloads. Integrate host profiling with automated detonation analysis.",
        "mitre_version": "16.1"
    }
