def get_content():
    return {
        "id": "T1564.006",
        "url_id": "T1564/006",
        "title": "Hide Artifacts: Run Virtual Instance",
        "description": "Adversaries may carry out malicious operations using a virtual instance to avoid detection. Running malware inside a guest VM can prevent monitoring and analysis by host-based security tools. Network traffic, filesystem writes, and malicious payloads can all be isolated within the virtual machine. This technique is also used to confuse attribution by separating the adversary's operations from the compromised host system.",
        "tags": ["virtual machine", "VM evasion", "VirtualBox", "Hyper-V", "QEMU", "headless VM"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Watch for signs of hypervisor startup such as VBoxManage or qemu-system binaries",
            "Monitor shared folder creation between host and guest",
            "Track command-line options for headless or silent VM launches"
        ],
        "data_sources": "Command, File, Image, Process, Service, Windows Registry",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Image", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Service", "source": "", "destination": ""},
            {"type": "Windows Registry", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "C:\\Program Files\\Oracle\\VirtualBox\\", "identify": "Presence of VBoxManage.exe or VM images"},
            {"type": "Process List", "location": "Task Manager or EDR", "identify": "Headless virtual machines or qemu-system processes"},
            {"type": "Registry Hives", "location": "HKLM\\SYSTEM\\ControlSet001\\Services", "identify": "Entries tied to virtualization software"}
        ],
        "destination_artifacts": [
            {"type": "Service", "location": "services.msc", "identify": "Auto-starting VM-related services"},
            {"type": "Image", "location": "Virtual disk containers (.vdi, .vmdk, .qcow2)", "identify": "Unusual or small-sized VMs"},
            {"type": "Command", "location": "CLI activity", "identify": "VBoxManage or Hyper-V commands with headless or silent flags"}
        ],
        "detection_methods": [
            "Monitor for installations or executions of virtualization software",
            "Alert on VBoxManage or qemu-system usage, especially in headless mode",
            "Watch for creation of services or registry keys associated with virtualization platforms"
        ],
        "apt": [
            "LoudMiner", "Maze", "Ragnar Locker"
        ],
        "spl_query": [
            "index=sysmon EventCode=1 \n| search CommandLine=*VBoxManage* OR *qemu-system* \n| stats count by CommandLine, Image, User",
            "index=wineventlog OR index=sysmon \n| search CommandLine=*--type headless* OR CommandLine=*GUI/SuppressMessages* \n| stats count by User, CommandLine",
            "index=registry \n| search RegistryPath=*\\Services\\VBox* OR RegistryPath=*\\Services\\VMware* \n| stats count by RegistryPath, RegistryValueData"
        ],
        "hunt_steps": [
            "Search for use of VBoxManage, qemu-system, or vmrun binaries",
            "Check for shared folder mappings between host and virtual instances",
            "Audit newly created Windows services related to virtualization software"
        ],
        "expected_outcomes": [
            "Detection of unauthorized virtual environments used for malicious execution",
            "Discovery of isolated malware hosted in guest systems",
            "Correlation between host and guest interactions for lateral movement or data staging"
        ],
        "false_positive": "Legitimate use of virtual machines is widespread in enterprise environments (e.g., development, sandboxing, security tools). Context is essential before classifying as malicious.",
        "clearing_steps": [
            "Stop and remove unauthorized virtual instances",
            "Remove virtualization software and supporting registry entries or services",
            "Audit for data exfiltration via shared folders or bridged network adapters"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1203", "example": "Launching attacker-controlled VM with malware payload"},
            {"tactic": "Defense Evasion", "technique": "T1036", "example": "Hiding behavior within guest OS to avoid detection by host sensors"}
        ],
        "watchlist": [
            "Unusual startup of virtual machine processes",
            "Installation of VirtualBox or QEMU on non-developer systems",
            "VM images stored in unexpected directories (e.g., AppData)"
        ],
        "enhancements": [
            "Enable detection of VM process signatures and API usage",
            "Alert on bridged or host-only networking adapters in use",
            "Correlate registry changes with virtualization software installs"
        ],
        "summary": "Running malicious activity inside a virtual instance allows adversaries to isolate and protect payloads from detection, complicate attribution, and facilitate hidden operations within enterprise environments.",
        "remediation": "Remove unauthorized VM platforms, delete suspicious VM containers, monitor shared folders, and enforce policy controls around virtualization use.",
        "improvements": "Deploy VM-aware EDR solutions, scan for shadowed VMs during IR, and implement policies limiting hypervisor installation or guest execution.",
        "mitre_version": "16.1"
    }
