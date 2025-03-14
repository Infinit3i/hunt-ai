def get_content():
    return {
        "id": "T1123",
        "url_id": "1123",
        "title": "Audio Capture",
        "description": "An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.",
        "tags": ["Audio Capture", "Malware", "Surveillance"],
        "tactic": "Collection",
        "protocol": "N/A",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Monitor API calls to microphone and recording devices.",
            "Detect unusual file writes containing audio data.",
            "Check for unauthorized processes accessing recording devices."
        ],
        "data_sources": "Command: Command Execution, Process: OS API Execution",
        "log_sources": [
            {"type": "Process", "source": "OS API Execution", "destination": "Monitoring System"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "Audio Recordings", "identify": "Sensitive Data"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "Exfiltration Channels", "identify": "Captured Audio"}
        ],
        "detection_methods": [
            "Monitor API calls related to microphone access.",
            "Detect processes writing audio files periodically.",
            "Check for unauthorized access to recording software."
        ],
        "apt": ["Transparent Tribe", "APT37", "ScarCruft"],
        "spl_query": ["| search process_name=microphone_capture"],
        "hunt_steps": [
            "Analyze logs for unusual audio capture activity.",
            "Identify processes accessing microphone APIs.",
            "Detect unexpected audio file creations."
        ],
        "expected_outcomes": [
            "Identify unauthorized audio capture attempts.",
            "Correlate audio capture activity with potential malware."
        ],
        "false_positive": "Legitimate applications such as conferencing software may access the microphone regularly.",
        "clearing_steps": [
            "Terminate unauthorized processes accessing the microphone.",
            "Restrict API access to microphone devices.",
            "Monitor system behavior for persistent threats."
        ],
        "mitre_mapping": [
            {"tactic": "Collection", "technique": "Screen Capture", "example": "T1113"}
        ],
        "watchlist": ["Unauthorized microphone access", "Unusual audio file creation"],
        "enhancements": ["Implement strict microphone access controls", "Utilize endpoint detection solutions"],
        "summary": "Attackers use microphone access to record and exfiltrate sensitive audio data.",
        "remediation": "Restrict microphone access, detect unauthorized recording, and monitor system logs.",
        "improvements": "Enhance monitoring capabilities for API interactions with audio devices."
    }
