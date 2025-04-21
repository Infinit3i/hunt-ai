def get_content():
    return {
        "id": "T1564.007",
        "url_id": "T1564/007",
        "title": "Hide Artifacts: VBA Stomping",
        "description": "Adversaries may hide malicious VBA macros in Microsoft Office documents by replacing the readable VBA source code with benign content while retaining the malicious p-code (compiled version of the macro). If the Office version on the victim machine matches the version specified in the _VBA_PROJECT stream, the p-code will execute, bypassing detection tools that analyze only the VBA source code. This technique is known as VBA stomping and can also prevent the GUI from showing the correct macro content.",
        "tags": ["VBA", "stomping", "p-code", "macro obfuscation", "oletools", "pcodedmp"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Windows, macOS",
        "tips": [
            "Extract and compare both VBA source code and p-code using tools like pcodedmp",
            "Scan Office documents for inconsistencies between _VBA_PROJECT and actual Office version",
            "Use dynamic analysis or GUI inspection to reveal hidden behavior"
        ],
        "data_sources": "File, Script",
        "log_sources": [
            {"type": "File", "source": "", "destination": ""},
            {"type": "Script", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "Embedded OLE streams within Office documents", "identify": "Modified _VBA_PROJECT or PROJECT stream"},
            {"type": "Script", "location": "p-code section", "identify": "Compiled macro without visible source code"},
            {"type": "File", "location": "Temporary files after document execution", "identify": "Indicators of macro behavior such as dropped payloads"}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "Office document attachments", "identify": "Macros with source-p-code mismatch"},
            {"type": "Script", "location": "Office application memory", "identify": "p-code present without source macro"},
            {"type": "File", "location": "User temp folders", "identify": "Artifact of macro execution or dropped files"}
        ],
        "detection_methods": [
            "Compare the presence of p-code and readable VBA source code using oletools or pcodedmp",
            "Inspect the PROJECT stream for undefined module names used to break GUI macro viewing",
            "Monitor macro-enabled documents with altered PerformanceCache structures"
        ],
        "apt": [
            "APT32", "FIN7", "TA551"
        ],
        "spl_query": [
            "index=filesource sourcetype=office_macro \n| search VBA_Stomping=True \n| stats count by FileName, DetectedMacroBehavior",
            "index=sysmon EventCode=1 \n| search CommandLine=*WINWORD.EXE* AND CommandLine=*macro* \n| stats count by ParentImage, CommandLine",
            "index=osquery \n| search file_path LIKE '%.docm' OR file_path LIKE '%.xlsm' \n| stats count by file_path, size, created_at"
        ],
        "hunt_steps": [
            "Search for macro-enabled Office documents (.docm, .xlsm) in user inboxes or download folders",
            "Use static analysis to extract and compare source VBA and compiled p-code",
            "Flag documents with VBA project mismatches or suppressed macro displays"
        ],
        "expected_outcomes": [
            "Identification of Office files containing malicious macros not visible in source code",
            "Detection of VBA projects with version-matching p-code designed to evade scanners",
            "Uncovering of macro execution that lacks readable script content"
        ],
        "false_positive": "Some development tools and legitimate Office projects may exhibit unusual VBA project structures. Confirm presence of obfuscation or behavior-based indicators before flagging.",
        "clearing_steps": [
            "Delete all macro-enabled documents that cannot be fully inspected",
            "Block execution of macros via GPO or Defender policies",
            "Alert users and IT teams to avoid opening suspicious macro documents"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1202", "example": "Abusing Office macro p-code execution to hide source code"},
            {"tactic": "Execution", "technique": "T1059.005", "example": "Macro-based execution without human-visible code"}
        ],
        "watchlist": [
            "Office documents with _VBA_PROJECT but no visible macros",
            "Office apps launching suspicious processes after opening documents",
            "Presence of modified PerformanceCache or undefined PROJECT module references"
        ],
        "enhancements": [
            "Deploy VBA-aware scanners that parse both p-code and source",
            "Correlate Office document opening events with macro execution logs",
            "Enforce macro signing or restrict to trusted publishers only"
        ],
        "summary": "VBA stomping hides malicious macros by replacing the readable source code with benign or empty data while retaining the executable p-code. This evades detection tools relying on source analysis and may allow malware to run undetected on systems with matching Office versions.",
        "remediation": "Remove macro-enabled documents with mismatched VBA structures, disable macros by default, and use p-code inspection tools during triage.",
        "improvements": "Expand signature-based scanning to include p-code parsing, implement secure macro execution policies, and alert on documents with undefined modules or corrupt streams.",
        "mitre_version": "16.1"
    }
