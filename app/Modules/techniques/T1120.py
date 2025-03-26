def get_content():
    return {
        "id": "T1120",
        "url_id": "T1120",
        "title": "Peripheral Device Discovery",
        "description": "Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system.",
        "tags": ["discovery", "usb", "peripherals", "device awareness", "host enumeration"],
        "tactic": "discovery",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Correlate USB enumeration commands with other reconnaissance or lateral movement activity",
            "Alert on unexpected use of WMI or PowerShell to query peripheral devices",
            "Monitor new USB device mounts in high-trust environments"
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "endpoint", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""},
            {"type": "Process", "source": "EDR", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "Microsoft-Windows-DriverFrameworks-UserMode/Operational", "identify": "Device connection logs"},
            {"type": "Windows Defender Logs", "location": "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History", "identify": "Detection of suspicious enumeration behavior"},
            {"type": "Registry Hives", "location": "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB", "identify": "Tracking connected USB and peripheral devices"}
        ],
        "destination_artifacts": [
            {"type": "Process List", "location": "Runtime process tree", "identify": "Commands or scripts querying peripherals"},
            {"type": "Command History", "location": "~/.bash_history or PowerShell logs", "identify": "Use of tools like lsusb, devmgmt.msc, Get-PnpDevice"},
            {"type": "Sysmon Logs", "location": "Event ID 1 & 10", "identify": "Execution of discovery commands targeting peripheral info"}
        ],
        "detection_methods": [
            "Detect usage of system tools like `lsusb`, `wmic`, `Get-PnpDevice`, or `devmgmt.msc`",
            "Flag enumeration of USB, smart card readers, webcams, or other input devices",
            "Behavioral correlation with follow-on lateral movement or credential access"
        ],
        "apt": [
            "TA505", "Qakbot", "WIRTE", "Patchwork", "Ramsay", "Sednit", "Transparent Tribe", "T9000", "Gamaredon", "BackdoorDiplomacy"
        ],
        "spl_query": [
            'index=sysmon EventCode=1 \n| search CommandLine="*Get-PnpDevice*" OR CommandLine="*wmic*" OR CommandLine="*lsusb*" \n| stats count by Image, CommandLine',
            'index=wineventlog EventCode=4688 \n| where CommandLine="*devmgmt.msc*" OR CommandLine="*enumerate*" \n| stats count by User, NewProcessName',
            'index=windows EventCode=20001 \n| search Message="Device connected" \n| stats count by Computer, DeviceID'
        ],
        "hunt_steps": [
            "Search for execution of device enumeration utilities",
            "Review driver framework event logs for unexpected device activity",
            "Identify scripting behavior associated with hardware discovery"
        ],
        "expected_outcomes": [
            "Detection of unauthorized attempts to query connected peripherals",
            "Insight into whether enumeration is part of pre-exfil or pre-persistence steps",
            "Context to correlate with data staging or credential theft via removable media"
        ],
        "false_positive": "Device inventory or IT asset management tools may run similar enumeration commands. Review user context and timing.",
        "clearing_steps": [
            "Remove unauthorized scripts or tools that gather hardware data",
            "Revoke device access for unknown users or processes",
            "Inspect for staged data or command logs indicating targeting of removable media"
        ],
        "mitre_mapping": [
            {"tactic": "collection", "technique": "T1005", "example": "File collection from removable devices"},
            {"tactic": "lateral-movement", "technique": "T1021.002", "example": "RDP initiated after peripheral discovery"},
            {"tactic": "execution", "technique": "T1059.001", "example": "PowerShell enumeration of PnP devices"}
        ],
        "watchlist": [
            "Execution of peripheral discovery tools on non-admin accounts",
            "Use of lsusb or Get-PnpDevice shortly before file access",
            "Mounting of multiple removable drives in short succession"
        ],
        "enhancements": [
            "Use EDR policies to block or alert on low-level USB enumeration commands",
            "Implement UAC prompts for running device discovery tools",
            "Deploy honeytokens via fake devices or dummy registry entries"
        ],
        "summary": "Peripheral Device Discovery allows adversaries to query the environment for connected hardware such as USB drives, webcams, or smart card readers. This knowledge can support subsequent stages such as exfiltration or credential harvesting.",
        "remediation": "Restrict access to hardware enumeration tools, monitor USB activity, and control scripting interfaces that could be abused for hardware discovery.",
        "improvements": "Integrate context-aware logging for device access, and alert on unexpected tool usage outside approved inventory scans.",
        "mitre_version": "16.1"
    }
