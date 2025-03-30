def get_content():
    return {
        "id": "T1497",
        "url_id": "T1497",
        "title": "Virtualization/Sandbox Evasion",
        "description": "Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox.",
        "tags": ["defense evasion", "discovery", "vm evasion", "sandbox detection", "anti-analysis", "environment awareness"],
        "tactic": "Defense Evasion, Discovery",
        "protocol": "",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Correlate sandbox evasion behavior with sudden termination or inactivity post environment checks.",
            "Use memory inspection to detect sleep-loop bypasses or conditional payloads.",
            "Enable verbose audit logging for process/thread creation tied to enumeration APIs.",
            "Deploy sandbox-aware deception tools that simulate user activity or artifacts."
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""},
            {"type": "Process", "source": "OS API Execution", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Loaded DLLs", "location": "Memory", "identify": "References to VM-related DLLs like vm3dgl.dll, vboxhook.dll"},
            {"type": "Process List", "location": "System", "identify": "Execution of processes like whoami.exe, systeminfo.exe, tasklist.exe in quick succession"},
            {"type": "Registry Hives", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Services", "identify": "Search for VMware or Vbox service keys"},
            {"type": "Environment Variables", "location": "System shell", "identify": "Unusual hardware specs or known sandbox user data"},
            {"type": "Memory Dumps", "location": "Sandboxed malware samples", "identify": "Anti-debugging or anti-vm instruction patterns"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Static analysis of binaries for anti-vm strings or timing loops.",
            "Dynamic behavior analysis using deception-based sandboxes.",
            "Monitor for bulk execution of reconnaissance commands (e.g., tasklist, wmic, systeminfo).",
            "Trace unusual API usage related to CPU/BIOS/VM detection."
        ],
        "apt": ["APT28", "Gamaredon", "Gelsemium", "Black Basta", "Bumblebee", "Squirrelwaffle", "CozyDuke", "Agent Tesla", "Carberp", "Hancitor", "Raspberry Robin", "DarkHotel", "Redaman", "Lyceum", "OutSteel", "SaintBot"],
        "spl_query": [
            'index=sysmon EventCode=1\n| search Image="*\\\\tasklist.exe" OR Image="*\\\\systeminfo.exe" OR Image="*\\\\whoami.exe"\n| stats count by ComputerName, ParentImage, Image',
            'index=sysmon EventCode=10\n| search CallTrace="*vmware*" OR CallTrace="*vbox*" OR CallTrace="*hyperv*"\n| stats count by ProcessId, Image, CallTrace',
            'index=os_logs\n| search command="*systeminfo*" OR command="*wmic*"\n| stats count by user, host'
        ],
        "hunt_steps": [
            "Scan for execution of system reconnaissance tools in quick succession.",
            "Analyze memory dumps for known sandbox evasion strings or patterns.",
            "Review API usage logs for system fingerprinting behavior.",
            "Check registry for known virtualization keys or services queried by malware."
        ],
        "expected_outcomes": [
            "Identification of malware evading analysis environments.",
            "Detection of conditional payload delivery logic.",
            "Visibility into early-stage discovery or anti-analysis techniques."
        ],
        "false_positive": "Security or system management tools may execute similar recon commands. Correlate with process parentage, command-line context, and timing.",
        "clearing_steps": [
            "Delete malware payload: del C:\\Users\\Public\\vm-aware-malware.exe /Q",
            "Clear registry keys created: reg delete HKCU\\Software\\MalwareVMChecks /f",
            "Reset system environment variables if altered",
            "Purge prefetch and shimcache data related to malicious executable",
            "Isolate system for memory analysis and reimage if compromise confirmed"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059", "example": "Payload executes only if virtualization checks fail"},
            {"tactic": "Defense Evasion", "technique": "T1027.002", "example": "Encrypted conditional payload released post-sandbox validation"}
        ],
        "watchlist": [
            "Processes querying hardware or VM identifiers",
            "Execution of common recon binaries in sandboxed environments",
            "API calls related to BIOS, CPU, registry, or system info in early stages",
            "Processes terminating shortly after recon attempts"
        ],
        "enhancements": [
            "Use deception VMs with spoofed user activity and system characteristics.",
            "Create correlation rules for bursty recon followed by process exit.",
            "Automate unpacking and memory scanning of conditional payloads post sandbox evasion."
        ],
        "summary": "Virtualization/Sandbox Evasion is used by adversaries to detect and avoid analysis environments like VMs and sandboxes, often by checking for specific artifacts, performing timing checks, or delaying execution to avoid detection.",
        "remediation": "Terminate and remove the malicious payload, delete related registry and persistence, inspect for conditional or delayed execution techniques, and rebuild the system if tampering is extensive.",
        "improvements": "Enhance sandbox realism, monitor process behavior chains, enable API logging at kernel and user level.",
        "mitre_version": "16.1"
    }
