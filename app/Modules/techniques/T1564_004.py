def get_content():
    return {
        "id": "T1564.004",
        "url_id": "T1564/004",
        "title": "Hide Artifacts: NTFS File Attributes",
        "description": "Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection. On NTFS-formatted volumes, file attributes such as Alternate Data Streams (ADS) and Extended Attributes (EA) can be used to store hidden content including malware, configurations, or arbitrary payloads. These attributes are not typically visible during standard file enumeration and can evade static AV tools or manual inspection.",
        "tags": ["NTFS", "alternate data stream", "ADS", "extended attributes", "metadata evasion", "ZwSetEaFile", "dir /r"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Use 'dir /r' to detect ADS on local files",
            "Leverage Sysinternals Streams.exe to scan for ADS",
            "Monitor usage of ZwSetEaFile and ZwQueryEaFile API functions"
        ],
        "data_sources": "Command, File, Process",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "C:\\NTFSVolume", "identify": "Files containing ADS or extended attributes"},
            {"type": "File Access Times (MACB Timestamps)", "location": "NTFS file system", "identify": "Timestamps may not change for ADS-only edits"},
            {"type": "Windows Defender Logs", "location": "Defender Scan History", "identify": "Indicators of flagged ADS payloads"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "syscalls or userland API calls", "identify": "ZwSetEaFile or ZwQueryEaFile used"},
            {"type": "File", "location": "ADS path: file.txt:hidden.txt", "identify": "Colon syntax implies ADS use"},
            {"type": "Command", "location": "PowerShell and cmd.exe logs", "identify": "Use of Get-Item -Stream or dir /r"}
        ],
        "detection_methods": [
            "Monitor command-line execution for dir /r, streams.exe, or PowerShell -Stream usage",
            "Inspect file metadata for presence of colon-separated data (e.g., file.txt:secret)",
            "Log and review API calls to ZwSetEaFile, ZwQueryEaFile, or relevant shell behavior"
        ],
        "apt": [
            "APT41", "LoJax", "PowerDuke", "Anchor", "Valak", "WastedLocker", "Regin", "Cobalt Kitty", "Indrik Spider"
        ],
        "spl_query": [
            "index=sysmon EventCode=1 \n| search CommandLine=*dir /r* OR CommandLine=*streams.exe* \n| stats count by Image, CommandLine, User",
            "index=wineventlog EventCode=13 \n| search RegistryPath=*ADS* \n| stats count by RegistryPath, EventID",
            "index=osquery \n| search file_path=*:* \n| stats count by file_path, username"
        ],
        "hunt_steps": [
            "Run 'dir /r' across user folders and program files",
            "Deploy streams.exe to scan NTFS volumes",
            "Search process creation logs for files accessed with ':' in the path"
        ],
        "expected_outcomes": [
            "Detection of suspicious ADS usage in user-accessible locations",
            "Uncovering of malicious payloads embedded within legitimate files",
            "Identification of obfuscated persistence mechanisms using NTFS attributes"
        ],
        "false_positive": "Some legitimate applications and system processes may use ADS or EA to store metadata or file information. Review paths and content before flagging as malicious.",
        "clearing_steps": [
            "Delete ADS using 'notepad file.txt:hidden.txt' to access and clear",
            "Use PowerShell's Remove-Item -Stream to remove hidden data",
            "Audit and replace impacted files with clean versions if ADS content is malicious"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1140", "example": "Using obfuscated payloads in ADS to avoid AV detection"},
            {"tactic": "Execution", "technique": "T1059.001", "example": "Running a script embedded in an ADS stream"}
        ],
        "watchlist": [
            "Processes executing files with : in path",
            "Unexpected EA or ADS creation in sensitive directories",
            "CommandLine usage of -stream, streams.exe, or dir /r"
        ],
        "enhancements": [
            "Enforce endpoint monitoring for ADS and EA changes",
            "Integrate ADS scanning into regular threat hunting workflows",
            "Correlate file access with creation/modification timestamps to detect stealth changes"
        ],
        "summary": "NTFS file attributes like Alternate Data Streams and Extended Attributes can be exploited by adversaries to hide malicious content outside of standard file content. These attributes often evade conventional file inspection and require specialized tools for detection.",
        "remediation": "Scan systems with tools like Sysinternals Streams, remove suspicious ADS content, and validate file integrity regularly.",
        "improvements": "Deploy automated scanning for ADS and EA during incident response and include forensic markers in EDR tools to detect hidden attributes.",
        "mitre_version": "16.1"
    }
