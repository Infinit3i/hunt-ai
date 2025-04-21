def get_content():
    return {
        "id": "T1564.001",
        "url_id": "T1564/001",
        "title": "Hide Artifacts: Hidden Files and Directories",
        "description": "Adversaries may set files and directories to be hidden to evade detection mechanisms. Most operating systems support a 'hidden' attribute or naming convention that conceals files from standard views. For instance, files prefixed with a dot (.) in Unix-based systems or those marked with the hidden attribute via attrib.exe in Windows may not be visible through GUI or basic command-line utilities. Adversaries leverage this to obscure tools, malware, and activity.",
        "tags": ["evasion", "hidden files", "directory manipulation", "artifact concealment", "attrib"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Use 'dir /a' on Windows and 'ls -a' on Linux/macOS to reveal hidden files.",
            "Hunt for attrib.exe or dot-prefixed filenames in user directories.",
            "Audit hidden folder creation in high-sensitivity paths (e.g., AppData, System32)."
        ],
        "data_sources": "Command, File, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Access Times (MACB Timestamps)", "location": "NTFS/EXT file systems", "identify": "Files with altered timestamps and hidden attributes"},
            {"type": "Registry Hives", "location": "HKCU or HKLM", "identify": "References to hidden folders or autoruns"},
            {"type": "Sysmon Logs", "location": "Microsoft-Windows-Sysmon/Operational", "identify": "File creation/modification with hidden flag"}
        ],
        "destination_artifacts": [
            {"type": "Prefetch Files", "location": "C:\\Windows\\Prefetch", "identify": "Execution of hidden tools"},
            {"type": "Loaded DLLs", "location": "Process memory", "identify": "Stealth DLLs residing in hidden folders"},
            {"type": "File", "location": "/tmp, ~/.ssh, C:\\ProgramData", "identify": "Hidden tool or script storage"}
        ],
        "detection_methods": [
            "Monitor usage of attrib.exe to set +h flag",
            "Detect dot-prefixed files in Linux/macOS user and temp directories",
            "Compare visible and actual contents using forensic tools or shell commands"
        ],
        "apt": [
            "Sofacy", "Agent Tesla", "TA416", "Rocke", "Transparent Tribe", "Calisto", "AppleJeus", "Nobelium", "Tropic Trooper", "HAFNIUM", "Black Basta"
        ],
        "spl_query": [
            "index=sysmon EventCode=1 \n| search CommandLine=*attrib*+h* \n| stats count by CommandLine, Image, ParentImage",
            "index=filetracker OR index=osquery \n| search Filename IN (*.tmp, .hidden) \n| stats count by FilePath, User",
            "index=sysmon EventCode=11 \n| search TargetFilename=*\\\\.* \n| stats count by TargetFilename, ProcessId"
        ],
        "hunt_steps": [
            "List hidden files: Windows: dir /a /s, Linux/macOS: find / -name '.*'",
            "Search startup folders and AppData for hidden directories",
            "Review Sysmon logs for execution or creation of hidden files"
        ],
        "expected_outcomes": [
            "Identification of hidden payloads or malicious tools",
            "Discovery of persistence mechanisms relying on hidden files",
            "Detection of attacker attempts to obfuscate malicious activity"
        ],
        "false_positive": "Some legitimate tools and applications use hidden files for configurations. Validate findings before assuming malicious intent.",
        "clearing_steps": [
            "Unhide files using 'attrib -h' or rename Unix dotfiles",
            "Remove hidden scripts, tools, or binaries not recognized",
            "Inspect affected user profiles for further manipulation"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1036", "example": "Disguising malicious files as hidden configuration files"},
            {"tactic": "Persistence", "technique": "T1547.001", "example": "Hidden scripts launched at startup"}
        ],
        "watchlist": [
            "Execution of attrib.exe",
            "Creation of .[filename] in user directories",
            "Hidden folders in AppData or ProgramData"
        ],
        "enhancements": [
            "Enable audit logging for attrib command",
            "Use EDR to capture process tree for hidden file actions",
            "Regularly scan for dot-prefixed and +h marked files"
        ],
        "summary": "Adversaries may hide files and directories using OS-supported methods to evade user and analyst detection. These tactics leverage UI design and system defaults to persist undetected.",
        "remediation": "Harden endpoint visibility with tools that uncover hidden files, regularly scan startup locations, and educate users on hidden file behavior.",
        "improvements": "Automate file system scans for hidden artifacts and correlate with process creation logs for context-aware detection.",
        "mitre_version": "16.1"
    }
