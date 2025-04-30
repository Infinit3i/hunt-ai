def get_content():
    return {
        "id": "T1219.003",
        "url_id": "T1219/003",
        "title": "Remote Access Hardware",
        "description": "An adversary may use legitimate remote access hardware to establish an interactive command and control channel to target systems within networks.",
        "tags": ["c2", "tinypilot", "pikvm", "kvm", "usb", "hardware", "bypass"],
        "tactic": "command-and-control",
        "protocol": "USB, IP-KVM",
        "os": "Windows, Linux, macOS",
        "tips": [
            "Restrict installation of peripheral devices that are not approved for enterprise use.",
            "Monitor USB and drive plug-in events, especially on sensitive systems.",
            "Audit physical access to hardware components that enable out-of-band control."
        ],
        "data_sources": "Drive",
        "log_sources": [
            {"type": "Drive", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Drive", "location": "/opt/tinypilot-privileged/init-usb-gadget", "identify": "Known TinyPilot USB gadget signatures (e.g., tinypilot, 6b65796d696d6570690)"}
        ],
        "destination_artifacts": [
            {"type": "Drive", "location": "/sys/class/drm/*/edid", "identify": "EDID strings including 'TinyPilot' or other known KVM signatures"}
        ],
        "detection_methods": [
            "Monitor USB and external hardware additions using OS and endpoint visibility tools.",
            "Inspect EDID data and declared USB vendor/product information for signs of TinyPilot/PiKVM.",
            "Use logging agents to detect device connection anomalies."
        ],
        "apt": [],
        "spl_query": [
            "(sourcetype=\"WinEventLog:Microsoft-Windows-DriverFrameworks-UserMode/Operational\" OR sourcetype=\"syslog\")(EventCode=2003 OR EventCode=2100 OR message=\"tinypilot\" OR message=\"TinyPilot\")\n| eval timestamp=_time\n| table timestamp, host, user, DeviceClass, FriendlyName, VendorID, ProductID, SerialNumber\n| sort by timestamp desc"
        ],
        "hunt_steps": [
            "Identify systems with recent unknown or suspicious USB hardware connections.",
            "Check connected devices for KVM device signatures (TinyPilot, PiKVM, etc.).",
            "Review video or keyboard/mouse event logs for remote manipulation."
        ],
        "expected_outcomes": [
            "Detection of stealthy out-of-band remote access hardware used for persistent access or evasion."
        ],
        "false_positive": "Legitimate use of KVM tools in datacenter or admin contexts. Validate by asset and user role.",
        "clearing_steps": [
            "Disconnect and physically remove unauthorized access hardware.",
            "Reimage impacted systems to eliminate potential remote manipulation footholds.",
            "Inspect BIOS/UEFI for potential KVM-level persistence modules."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "command-and-control", "technique": "T1219", "example": "Remote Access Tools"},
            {"tactic": "defense-evasion", "technique": "T1202", "example": "Indirect Command Execution"}
        ],
        "watchlist": [
            "tinypilot or pikvm devices connected to high-value endpoints",
            "USB device installs with unknown vendor/product IDs"
        ],
        "enhancements": [
            "Restrict USB port usage on sensitive endpoints.",
            "Use device control policies to block unapproved hardware by vendor ID."
        ],
        "summary": "Remote access hardware like TinyPilot and PiKVM can give adversaries full out-of-band control over a system while bypassing software security controls.",
        "remediation": "Physically audit and remove unauthorized access devices and enforce hardware whitelisting policies.",
        "improvements": "Deploy USB monitoring and block listing solutions to detect and prevent unauthorized peripheral use.",
        "mitre_version": "17.0"
    }
