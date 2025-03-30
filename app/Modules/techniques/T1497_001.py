def get_content():
    return {
        "id": "T1497.001",
        "url_id": "T1497/001",
        "title": "Virtualization/Sandbox Evasion: System Checks",
        "description": "Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox.",
        "tags": ["defense evasion", "discovery", "vm detection", "sandbox detection", "environment checks", "systeminfo"],
        "tactic": "Defense Evasion, Discovery",
        "protocol": "",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Monitor for execution of common recon and discovery tools early in execution.",
            "Detect presence of scripts that chain WMI, registry, and PowerShell-based checks.",
            "Flag processes that search for 'malware', 'sample', or VM identifiers in file paths or hardware.",
            "Use behavioral sandboxes that simulate user activity and modify environment fingerprints."
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""},
            {"type": "Process", "source": "OS API Execution", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Registry Hives", "location": "HKLM\\SYSTEM", "identify": "VM-specific entries like VBoxService or VMWare Tools"},
            {"type": "Loaded DLLs", "location": "Memory", "identify": "Libraries related to virtualization (e.g., vboxhook.dll, vm3dgl.dll)"},
            {"type": "Process List", "location": "System Info", "identify": "PowerShell scripts using systeminfo, wmic, or Get-WmiObject"},
            {"type": "File Access Times (MACB)", "location": "Virtual environment file paths", "identify": "Malware inspecting unusual file or folder names like 'sample', 'sandbox'"},
            {"type": "Event Logs", "location": "Security and Sysmon", "identify": "Burst of recon activity shortly after initial execution"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Correlate bursty recon behaviors across processes using system discovery tools.",
            "Static analysis to detect combined use of WMI, registry, and hardware-check routines.",
            "Behavioral detection of malware self-terminating or delaying execution if in a VM.",
            "Detection of command-line strings referencing 'VirtualBox', 'vmware', 'sandbox', or similar."
        ],
        "apt": [
            "APT10", "APT28", "OilRig", "PlugX", "QakBot", "GuLoader", "DarkHydrus",
            "EvilNum", "Frankenstein", "WIRTE", "Bumblebee", "Latrodectus", "Black Basta",
            "Snip3", "Daggerfly", "SynAck", "Cobalt Kitty", "Volt Typhoon", "Raspberry Robin"
        ],
        "spl_query": [
            'index=sysmon EventCode=1\n| search Image="*\\\\powershell.exe" AND CommandLine="*Get-WmiObject*" OR CommandLine="*systeminfo*" OR CommandLine="*wmic*" OR CommandLine="*Select-String*"',
            'index=sysmon EventCode=10\n| search CallTrace="*vmware*" OR CallTrace="*vbox*" OR CallTrace="*virtual*"',
            'index=registry_logs\n| search registry_path="*VBox*" OR registry_path="*VMware*" OR registry_path="*QEMU*"'
        ],
        "hunt_steps": [
            "Look for scripts combining registry, WMI, and system checks executed in one burst.",
            "Analyze for process trees that execute recon commands followed by self-exit or sleep.",
            "Correlate registry queries to known VM-related keys with other reconnaissance behavior.",
            "Inspect malware samples for embedded strings or obfuscated virtualization checks."
        ],
        "expected_outcomes": [
            "Detection of malware using automated system and registry checks to determine analysis environment.",
            "Identification of payloads conditioned on virtual presence.",
            "Visibility into early evasion techniques attempting to abort execution or load decoys."
        ],
        "false_positive": "System monitoring and administrative scripts may use similar recon commands. Focus on execution context, burst timing, and follow-up behavior for accuracy.",
        "clearing_steps": [
            "Terminate script or binary executing checks: taskkill /F /IM sandbox-checker.exe",
            "Remove persistence if script was embedded in startup: reg delete HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v check /f",
            "Delete temp files or logs written to disk: del C:\\Users\\Public\\ReconLogs\\* /Q",
            "Clear loaded modules from memory if resident: use memory scanner or reboot clean"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1082", "example": "systeminfo.exe used to profile host"},
            {"tactic": "Discovery", "technique": "T1012", "example": "Registry queries for VM-related keys"},
            {"tactic": "Discovery", "technique": "T1047", "example": "WMI commands to detect virtual environment"}
        ],
        "watchlist": [
            "Script chains that enumerate system + registry + memory + file paths",
            "Use of anti-vm DLLs and instruction sets (e.g., CPUID, I/O port 0x5658)",
            "Command-line arguments referencing analysis artifacts or known research VMs",
            "Self-terminating binaries post discovery attempts"
        ],
        "enhancements": [
            "Implement sandbox evasion bypass emulation for test detonation.",
            "Deploy hooks to trace CPUID, I/O port, and sysinfo system calls.",
            "Correlate recon behaviors to sudden binary inactivity (timeout, exit, or sleep)."
        ],
        "summary": "System Checks are used by adversaries to determine whether malware is executing in a sandbox or virtual environment, typically by gathering hardware, registry, and environment data. The outcome is used to gate payload delivery or evade detection.",
        "remediation": "Terminate malware, purge any dropped payloads, delete recon scripts or binaries, clear related registry changes, and validate system logs.",
        "improvements": "Enhance behavioral detection through correlation rules, emulate artifact presence in test environments, and flag conditional code branches used in evasion.",
        "mitre_version": "16.1"
    }
