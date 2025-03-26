def get_content():
    return {
        "id": "T1113",
        "url_id": "T1113",
        "title": "Screen Capture",
        "description": "Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation.",
        "tags": ["screen capture", "surveillance", "collection", "screenshot", "image logging"],
        "tactic": "collection",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Detect use of known screen capture utilities or suspicious image libraries",
            "Monitor for screen capture API calls like BitBlt, CopyFromScreen, or screencapture",
            "Flag unexpected image file creation in temp or user profile directories"
        ],
        "data_sources": "Command, Process",
        "log_sources": [
            {"type": "Command", "source": "endpoint", "destination": ""},
            {"type": "Process", "source": "EDR", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Prefetch Files", "location": "C:\\Windows\\Prefetch\\", "identify": "Execution of tools like screen capture scripts or screenshot.exe"},
            {"type": "Recent Files", "location": "C:\\Users\\<user>\\AppData\\Local\\Temp", "identify": "Images with screen content or timestamped PNGs/JPGs"},
            {"type": "Windows Defender Logs", "location": "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History", "identify": "Behavioral detection of screen capture tools"}
        ],
        "destination_artifacts": [
            {"type": "Image", "location": "User profile temp or roaming folders", "identify": "Captured screenshots (.bmp, .png, .jpeg)"},
            {"type": "Clipboard Data", "location": "Memory or clip logs", "identify": "Screen snippets copied via malicious process"},
            {"type": "Shellbags", "location": "NTUSER.DAT", "identify": "Evidence of access to screenshot directories"}
        ],
        "detection_methods": [
            "Alert on use of screen capture commands or native OS screenshot utilities",
            "Detect processes using APIs like BitBlt or CopyFromScreen from .NET or PowerShell",
            "Monitor unusual image file creation patterns in unexpected locations"
        ],
        "apt": [
            "Gamaredon", "Ursnif", "InvisiMole", "Chaes", "TA505", "APT10", "APT33", "APT34", "Valak", "Zebrocy", "BRONZE BUTLER", "Metador"
        ],
        "spl_query": [
            'index=sysmon EventCode=1 \n| search CommandLine="*screenshot*" OR CommandLine="*screen*" \n| stats count by Image, CommandLine',
            'index=sysmon EventCode=11 \n| search TargetFilename="*.png" OR TargetFilename="*.bmp" OR TargetFilename="*.jpg" \n| stats count by TargetFilename, ProcessId',
            'index=sysmon EventCode=7 \n| search ImageLoaded="*user32.dll" OR ImageLoaded="*gdi32.dll" \n| stats count by Image, ImageLoaded'
        ],
        "hunt_steps": [
            "Search for unusual image file creation under AppData, Temp, or public folders",
            "Check for use of BitBlt, PrintWindow, or CopyFromScreen via process memory or execution logs",
            "Investigate persistence methods related to screen capture scheduled tasks or registry"
        ],
        "expected_outcomes": [
            "Detection of unauthorized screen capture activity",
            "Identification of image-based surveillance from compromised endpoints",
            "Attribution of tools used in post-exploitation collection phase"
        ],
        "false_positive": "Legitimate use of screenshots for documentation or helpdesk tickets. Validate context, frequency, and image storage location.",
        "clearing_steps": [
            "Delete collected screenshots and related scripts/tools",
            "Terminate processes or scheduled tasks used for recurring screen capture",
            "Re-image compromised machines or apply endpoint hardening policies"
        ],
        "mitre_mapping": [
            {"tactic": "collection", "technique": "T1119", "example": "Capture of clipboard and screen content simultaneously"},
            {"tactic": "defense-evasion", "technique": "T1140", "example": "Screen capture payload hidden via encryption"},
            {"tactic": "exfiltration", "technique": "T1048.003", "example": "Screenshots exfiltrated via Dropbox or HTTP POST"}
        ],
        "watchlist": [
            "Unusual frequency of .png/.bmp/.jpg file generation",
            "Processes calling Win32 or .NET screen APIs without GUI context",
            "Screen captures saved then immediately deleted"
        ],
        "enhancements": [
            "Apply DLP solutions to monitor sensitive visual content capture",
            "Implement behavior-based blocking for automated screenshotting tools",
            "Use EDR to restrict API usage (BitBlt, PrintWindow, etc.) to trusted apps"
        ],
        "summary": "Screen capture techniques are often used post-compromise to collect sensitive visual information such as credentials, sensitive documents, or user activity directly from the victim's desktop.",
        "remediation": "Restrict screen capture API use, log creation of image files in key directories, and scan for tools used in RMM and RAT frameworks.",
        "improvements": "Correlate screen capture with clipboard activity and keystrokes for multi-channel intelligence. Integrate alerts with user behavior analytics.",
        "mitre_version": "16.1"
    }
