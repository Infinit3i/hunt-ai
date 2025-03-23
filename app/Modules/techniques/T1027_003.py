def get_content():
    return {
        "id": "T1027.003",
        "url_id": "T1027/003",
        "title": "Obfuscated Files or Information: Steganography",
        "description": "Adversaries may hide data inside images, audio, video, or text using steganography techniques to evade detection.",
        "tags": ["evasion", "steganography", "covert", "obfuscation", "image hiding"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Analyze images, audio, or text for unexpected metadata or file size inconsistencies.",
            "Use steganalysis tools to detect hidden data in media files.",
            "Correlate image files being uploaded/downloaded during odd times with suspicious process execution."
        ],
        "data_sources": "File: File Metadata",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File Metadata", "location": "User Downloads or Temp folder", "identify": "Unusual image/audio files with abnormal sizes"},
            {"type": "Clipboard Data", "location": "System Memory", "identify": "Payloads copied from decoded media"},
            {"type": "Memory Dumps", "location": "Runtime", "identify": "Decoded stego payload during script execution"}
        ],
        "destination_artifacts": [
            {"type": "File Metadata", "location": "User Profile Folders", "identify": "Images modified or created during off-hours"},
            {"type": "Windows Defender Logs", "location": "Security logs", "identify": "Heuristic detection of suspicious embedded content"},
            {"type": "Recent Files", "location": "NTUSER.DAT", "identify": "Recently opened stego carrier files"}
        ],
        "detection_methods": [
            "Signature analysis of known stego tools",
            "File size anomaly detection for image/audio content",
            "Monitor use of scripting tools to extract payloads from media files"
        ],
        "apt": [
            "Dukes", "RAINDROP", "Group123", "PowerDuke", "Tick", "TA551", "ScarCruft", "Tropic Trooper", "Oblique RAT",
            "Ramsay", "IcedID", "Spalax", "Bandook", "RDAT", "Andariel", "EarthLusca", "Okrum", "Lazarus", "MuddyWater", "APT40", "Diavol", "Pikabot"
        ],
        "spl_query": [
            'index=network_logs file_name="*.png" OR file_name="*.jpg" OR file_name="*.mp3" OR file_name="*.mp4"\n| eval file_size_mb=length(file_content)/1024/1024\n| where file_size_mb > 10 AND file_type="image"',
            'index=endpoint_logs process_name="powershell.exe" OR process_name="python.exe" command_line="*Invoke-PSImage*"\n| stats count by user, host, command_line'
        ],
        "hunt_steps": [
            "Search for use of tools like Invoke-PSImage, Steghide, or OutGuess",
            "Check for abnormally large media files downloaded from suspicious domains",
            "Review unusual access of image/audio/video files by scripting tools or shells"
        ],
        "expected_outcomes": [
            "Detection of payloads hidden within common media file types",
            "Identification of PowerShell or script usage to decode and execute stego content",
            "Discovery of image files acting as malware carriers"
        ],
        "false_positive": "High-resolution media or legitimate protected content may trigger size-based rules. Correlate with process behavior for accuracy.",
        "clearing_steps": [
            "Delete carrier files with embedded payloads",
            "Quarantine processes extracting or executing hidden data",
            "Reimage machines used to host or decode suspicious stego content"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1059.001", "example": "PowerShell decoding image and executing embedded payload"},
            {"tactic": "Command and Control", "technique": "T1043", "example": "Exfiltrating stego-encoded images to C2 server"}
        ],
        "watchlist": [
            "PowerShell invoking image-based execution tools",
            "Abnormally large or modified image/audio files in user profiles",
            "Outbound traffic involving image uploads to uncommon domains"
        ],
        "enhancements": [
            "Deploy steganography detection tools in security appliance stacks",
            "Use content inspection proxies for media files",
            "Incorporate file size baselines per filetype"
        ],
        "summary": "Steganography is used by adversaries to conceal malicious payloads inside otherwise benign-looking files such as images, videos, or audio. These methods are difficult to detect using traditional antivirus or hash-based techniques.",
        "remediation": "Block or monitor use of steganography tools. Isolate affected hosts and perform full memory and disk forensics.",
        "improvements": "Implement behavioral rules for file access by scripting engines and media file analysis thresholds.",
        "mitre_version": "16.1"
    }
