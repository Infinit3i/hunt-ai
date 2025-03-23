def get_content():
    return {
        "id": "T1052.001",
        "url_id": "T1052/001",
        "title": "Exfiltration Over Physical Medium: Exfiltration over USB",
        "description": "Adversaries may exfiltrate data via a USB device. In air-gapped network compromises, exfiltration can occur through USB devices introduced by users. The USB device could be used to exfiltrate data directly or to move between disconnected systems.",
        "tags": ["Exfiltration", "USB", "Removable Media"],
        "tactic": "Exfiltration",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": ["Monitor file access on removable media.", "Detect processes that execute when media is mounted."],
        "data_sources": "Command: Command Execution, Drive: Drive Creation, File: File Access, Process: Process Creation",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "Drive", "source": "Drive Creation", "destination": ""},
            {"type": "File", "source": "File Access", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Drive", "location": "Drive Creation", "identify": "USB device connected for exfiltration"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "File Access", "identify": "Files copied to USB device for exfiltration"}
        ],
        "detection_methods": ["Monitor for file access on removable media.", "Watch for processes executing upon media mounting."],
        "apt": [],
        "spl_query": [],
        "hunt_steps": ["Search for unusual file access patterns involving USB devices.", "Monitor for process creation triggered by USB devices."],
        "expected_outcomes": ["Identification of data being transferred to USB devices.", "Detection of suspicious USB devices interacting with the system."],
        "false_positive": "Legitimate use of USB devices by authorized users.",
        "clearing_steps": ["Terminate unauthorized processes interacting with USB devices.", "Ensure all USB devices are scanned for exfiltrated data."],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1052", "example": "Data exfiltrated to a USB device."}
        ],
        "watchlist": ["Monitor for the insertion of unauthorized USB devices."],
        "enhancements": ["Enable autorun detection to prevent automatic execution from USB devices.", "Monitor for suspicious USB device connections."],
        "summary": "Exfiltration over USB devices allows adversaries to transfer data via physical mediums, bypassing network-based monitoring.",
        "remediation": "Limit the use of USB devices and implement strict access controls.",
        "improvements": "Implement device control policies to restrict unauthorized external devices.",
        "mitre_version": "16.1"
    }
