def get_content():
    return {
        "id": "T1052",
        "url_id": "T1052",
        "title": "Exfiltration Over Physical Medium",
        "description": "Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. This can occur in scenarios like air-gapped network compromises, where the exfiltration point is a physical device introduced by a user. Devices such as USB drives, external hard drives, MP3 players, or mobile phones could be used to transfer data. The physical medium can be the final exfiltration point or act as a bridge between disconnected systems.",
        "tags": ["Exfiltration", "Physical Medium", "Removable Media"],
        "tactic": "Exfiltration",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": ["Monitor file access on removable media.", "Detect processes that execute upon media mounting."],
        "data_sources": "Command: Command Execution, Drive: Drive Creation, File: File Access, Process: Process Creation",
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "Drive", "source": "Drive Creation", "destination": ""},
            {"type": "File", "source": "File Access", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Drive", "location": "Drive Creation", "identify": "Removable media being used for data exfiltration"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "File Access", "identify": "Files transferred from system to external device"}
        ],
        "detection_methods": ["Monitor for file access on removable media.", "Watch for processes that execute when media is mounted."],
        "apt": [],
        "spl_query": [],
        "hunt_steps": ["Search for unusual file access patterns involving removable media.", "Monitor for process creation triggered by external media."],
        "expected_outcomes": ["Identification of data being transferred via physical medium.", "Detection of suspicious external devices interacting with the system."],
        "false_positive": "Legitimate usage of removable media by authorized users.",
        "clearing_steps": ["Terminate any unauthorized processes interacting with removable media.", "Ensure all physical devices are scanned for exfiltrated data."],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1052", "example": "Data transferred to a USB drive for exfiltration"}
        ],
        "watchlist": ["Monitor for the insertion of unknown or unauthorized removable devices."],
        "enhancements": ["Enable autorun detection to prevent automatic execution from removable media.", "Monitor for unusual device connections to the network."],
        "summary": "Exfiltration over physical mediums involves transferring data through removable storage devices, potentially bridging air-gapped systems.",
        "remediation": "Limit the use of removable media and implement strict access controls.",
        "improvements": "Implement device control policies to restrict unauthorized external devices.",
        "mitre_version": "16.1"
    }
