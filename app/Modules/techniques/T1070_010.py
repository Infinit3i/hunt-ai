def get_content():
    return {
        "id": "T1070.010",
        "url_id": "T1070/010",
        "title": "Indicator Removal: Relocate Malware",
        "description": "Once a payload is delivered, adversaries may reproduce copies of the same malware on the victim system to remove evidence of their presence and/or avoid defenses. Copying malware payloads to new locations may also be combined with File Deletion to cleanup older artifacts.",
        "tags": ["defense evasion", "malware relocation", "file modification", "blending in", "payload movement"],
        "tactic": "defense-evasion",
        "protocol": "",
        "os": "Windows, Linux, macOS, Network",
        "tips": [
            "Correlate file creation events with known malware behavior",
            "Alert on renamed executables in unusual directories",
            "Monitor known persistence folders for unexpected binaries"
        ],
        "data_sources": "File",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "C:\\Users\\<user>\\Downloads", "identify": "Initial malware drop location"},
            {"type": "File", "location": "/tmp or /var/tmp", "identify": "Staging locations on Linux"},
            {"type": "File", "location": "~/Library/Application Support/", "identify": "Relocation on macOS"},
            {"type": "File", "location": "C:\\ProgramData\\", "identify": "Malware moving to blend with system files"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "C:\\Windows\\System32", "identify": "Payload renamed to match legitimate file"},
            {"type": "File", "location": "/usr/bin/", "identify": "Linux malware copied to mimic system utility"}
        ],
        "detection_methods": [
            "Track movement of suspicious files between directories",
            "Detect file copies immediately followed by deletion of original",
            "Use file reputation and behavioral analytics to flag unknown binaries",
            "Monitor for binaries using known legitimate filenames or paths"
        ],
        "apt": ["Trickbot", "Latrodectus"],
        "spl_query": [
            "index=sysmon EventCode=11 TargetFilename=\"*.exe\" \n| transaction TargetFilename maxspan=5s \n| where eventcount > 1 \n| table _time, TargetFilename, Image, user",
            "index=sysmon EventCode=1 CommandLine=\"*copy*\" OR CommandLine=\"*move*\" \n| stats count by host, user, CommandLine",
            "index=edr_logs event_type=file_move dest_path=\"C:\\ProgramData\\*\" \n| stats count by user, dest_path"
        ],
        "hunt_steps": [
            "Review file creation and movement logs for repeated relocations of the same hash",
            "Check if binaries are copied to paths with file exclusions or persistence potential",
            "Identify renaming of files to names mimicking OS or common software binaries"
        ],
        "expected_outcomes": [
            "Payloads appear in new locations with original deleted",
            "Malware renamed to appear legitimate",
            "Artifacts disconnected from initial delivery vector"
        ],
        "false_positive": "Legitimate file management scripts, installers, or software updates may relocate executables. Validate file hash reputation and verify with sysadmin teams.",
        "clearing_steps": [
            "del C:\\Users\\<user>\\Downloads\\<malware>.exe",
            "move <malware>.exe C:\\Windows\\System32\\svchost.exe",
            "mv /tmp/malware.sh /usr/bin/systemctl"
        ],
        "mitre_mapping": [
            {"tactic": "defense-evasion", "technique": "T1036.005", "example": "Rename payload to match legitimate filename"},
            {"tactic": "defense-evasion", "technique": "T1564.012", "example": "Relocate to directories excluded by antivirus"},
            {"tactic": "persistence", "technique": "T1547.001", "example": "Relocation to persistence folder after install"}
        ],
        "watchlist": [
            "Executables written to C:\\Windows or ProgramData",
            "Files moved from user folders to system folders",
            "Same file hash appearing in multiple paths in short time"
        ],
        "enhancements": [
            "Enable file integrity monitoring on system directories",
            "Alert on hash reuse in separate directories",
            "Use endpoint rules to flag binary moves followed by deletions"
        ],
        "summary": "Adversaries may relocate malware after delivery to hide origin, avoid detection, and blend with legitimate files. This often includes copying then deleting the original, or moving to known persistence or excluded locations.",
        "remediation": "Quarantine relocated files, verify integrity of affected directories, and review surrounding timeline for related activities (e.g., initial delivery, user execution).",
        "improvements": "Combine file creation, deletion, and movement telemetry with EDR correlation to improve alerting on relocation behaviors.",
        "mitre_version": "16.1"
    }
