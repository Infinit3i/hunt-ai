def get_content():
    return {
        "id": "T1200",
        "url_id": "T1200",
        "title": "Hardware Additions",
        "tags": ["Physical Access", "Persistence", "Initial Access"],
        "tactic": "Initial Access",
        "data_sources": "USB Device Logs, Network Traffic Analysis, Process Monitoring, File System Monitoring",
        "protocol": "USB, Bluetooth, Serial",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate unauthorized hardware devices used for persistence or initial access.",
        "scope": "Monitor for unauthorized hardware additions that may be used for malicious purposes.",
        "threat_model": "Adversaries may introduce rogue hardware devices, such as keyloggers, network implants, or USB HID attack tools, to compromise systems or maintain persistence.",
        "hypothesis": [
            "Are there unauthorized USB devices connecting to critical systems?",
            "Are new hardware components being installed without proper authorization?",
            "Are attackers leveraging rogue devices for persistence mechanisms?"
        ],
        "tips": [
            "Restrict USB and external device usage on critical endpoints.",
            "Monitor network traffic for anomalous behavior linked to new devices.",
            "Implement endpoint protection to block unauthorized hardware installations."
        ],
        "log_sources": [
            {"type": "System Logs", "source": "Windows Event ID 2003 (USB Device Plug-In)", "destination": "Security Logs"},
            {"type": "Network Traffic", "source": "Packet captures of unauthorized device communication", "destination": "SIEM"},
            {"type": "File System", "source": "Monitoring new device installations", "destination": "Endpoint Protection Logs"}
        ],
        "source_artifacts": [
            {"type": "Hardware Device", "location": "Physical Endpoint", "identify": "Identify unauthorized USB or network implants."}
        ],
        "destination_artifacts": [
            {"type": "Malware Payload", "location": "Compromised System", "identify": "Detect files dropped by rogue hardware devices."}
        ],
        "detection_methods": [
            "Monitor for unauthorized USB or Bluetooth device connections.",
            "Analyze network traffic for unknown devices communicating with external IPs.",
            "Use endpoint monitoring to detect new hardware additions or changes."
        ],
        "apt": ["Equation Group", "FIN7", "APT28"],
        "spl_query": [
            "index=security sourcetype=WinEventLog EventCode=2003 USBDeviceConnected=TRUE",
            "index=network_logs sourcetype=pcap new_device_detected=TRUE"
        ],
        "hunt_steps": [
            "Identify new or unauthorized hardware devices added to critical endpoints.",
            "Correlate device connection logs with known malicious hardware signatures.",
            "Analyze endpoint logs for unauthorized device interactions.",
            "Investigate any newly installed drivers associated with unapproved hardware.",
            "If unauthorized device is detected → Isolate the system and remove the device."
        ],
        "expected_outcomes": [
            "Unauthorized hardware detected and removed: Security controls reinforced.",
            "No malicious activity found: Strengthen monitoring and access policies."
        ],
        "false_positive": "Legitimate USB peripherals, external storage devices, or network adapters used by authorized personnel.",
        "clearing_steps": [
            "Physically remove unauthorized devices.",
            "Disable USB and external device access for non-essential users.",
            "Update security policies to prevent hardware-based threats."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1098 (Account Manipulation)", "example": "Hardware keyloggers used to capture credentials."},
            {"tactic": "Execution", "technique": "T1204.002 (User Execution - Malicious File)", "example": "Malware execution triggered via unauthorized USB devices."},
            {"tactic": "Command and Control", "technique": "T1090 (Proxy)", "example": "Hardware implants creating covert network tunnels."}
        ],
        "watchlist": [
            "Monitor for new device installations on sensitive endpoints.",
            "Detect unauthorized USB devices connecting to servers.",
            "Alert on abnormal data transfers initiated by new hardware."
        ],
        "enhancements": [
            "Enforce strict device control policies to limit unauthorized hardware.",
            "Regularly audit connected devices and USB logs.",
            "Implement behavioral analytics for abnormal hardware interactions."
        ],
        "summary": "Adversaries may introduce rogue hardware devices to gain initial access or persist on compromised systems.",
        "remediation": "Physically inspect and remove unauthorized devices, restrict hardware additions, and monitor system logs for anomalies.",
        "improvements": "Enhance USB and device control policies, integrate hardware-based threat detection into SIEM, and conduct regular endpoint security audits."
    }
