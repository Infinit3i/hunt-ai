def get_content():
    return {
        "id": "T1547.015",
        "url_id": "1547/015",
        "title": "Boot or Logon Autostart Execution: Login Items",
        "description": "Adversaries may add login items to execute upon user login to gain persistence or escalate privileges.",
        "tags": ["Persistence", "Privilege Escalation", "macOS"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "macOS",
        "os": "macOS",
        "tips": [
            "Monitor login item modifications in System Preferences and '~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm'.",
            "Track abnormal login items using 'LSUIElement' or 'LSBackgroundOnly' in Info.plist.",
            "Analyze startup applications for unexpected network connections."
        ],
        "data_sources": "File: File Creation, File: File Modification, Process: Process Creation",
        "log_sources": [
            {"type": "File", "source": "Login Items", "destination": "Security Monitoring"},
            {"type": "Process", "source": "Startup Applications", "destination": "SIEM"}
        ],
        "source_artifacts": [
            {"type": "File", "location": "~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm", "identify": "Login Item Entries"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "Contents/Library/LoginItems", "identify": "Application Login Items"}
        ],
        "detection_methods": [
            "Monitor login item file changes in backgroundtaskmanagementagent.",
            "Detect new or modified login item scripts in '~/Library/LaunchAgents'.",
            "Analyze startup application behavior for privilege escalation attempts."
        ],
        "apt": ["Green Lambert", "NETWIRE"],
        "spl_query": [
            "index=macos_logs | search file_path='/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm'",
            "index=process_creation | search command contains 'osascript' OR 'SMLoginItemSetEnabled'"
        ],
        "hunt_steps": [
            "Identify newly added login items and determine their source.",
            "Check if login items execute suspicious or unauthorized binaries."
        ],
        "expected_outcomes": [
            "Detection of unauthorized login item modifications.",
            "Identification of adversaries using login items for persistence."
        ],
        "false_positive": "Legitimate software often adds login items for startup configurations.",
        "clearing_steps": [
            "Remove unauthorized login items from '~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm'.",
            "Manually inspect and delete suspicious login items in System Preferences."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1059.002", "example": "Execution via AppleScript Login Item Manipulation"},
            {"tactic": "Privilege Escalation", "technique": "T1106", "example": "Using Native API to Register Malicious Login Items"}
        ],
        "watchlist": [
            "Monitor new login items that are not associated with known software.",
            "Alert on unauthorized applications requesting login item persistence."
        ],
        "enhancements": [
            "Implement application whitelisting for login items.",
            "Restrict user ability to modify login items without administrative approval."
        ],
        "summary": "Adversaries may add login items to execute upon user login to gain persistence or escalate privileges.",
        "remediation": "Restrict unauthorized login item modifications and audit changes regularly.",
        "improvements": "Regularly review login item configurations for unauthorized entries."
    }
