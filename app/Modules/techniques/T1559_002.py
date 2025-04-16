def get_content():
    return {
        "id": "T1559.002",
        "url_id": "T1559/002",
        "title": "Inter-Process Communication: Dynamic Data Exchange",
        "description": "Adversaries may abuse Windows Dynamic Data Exchange (DDE) to execute commands via inter-process communication. DDE links allow Office or other Windows apps to autonomously exchange data or trigger execution through embedded fields. This can be used for code execution without macros, often via phishing or document-based attacks.",
        "tags": ["dde", "excel", "csv injection", "office exploit", "execution", "phishing", "command execution"],
        "tactic": "Execution",
        "protocol": "",
        "os": "Windows",
        "tips": [
            "Disable DDEAUTO functionality via registry or GPO when not in use.",
            "Inspect Office documents and CSVs for embedded DDE strings or execution triggers.",
            "Enable Protected View and ASR rules to prevent automated process spawning."
        ],
        "data_sources": "Module, Process, Script",
        "log_sources": [
            {"type": "Module", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""},
            {"type": "Script", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Script Execution", "location": "Document Object", "identify": "DDEAUTO, DDE field or CSV injection"},
            {"type": "Process", "location": "System Logs", "identify": "Office application spawning unexpected child processes"},
            {"type": "File", "location": "Downloads or Email Attachments", "identify": "Embedded DDE field in Office/CSV file"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "Office Child Process Tree", "identify": "Spawned cmd.exe, powershell.exe, or mshta.exe"},
            {"type": "Script", "location": "Temp or AppData", "identify": "Payloads dropped by DDE execution"},
            {"type": "Module", "location": "System32", "identify": "DLLs dynamically loaded by Office"}
        ],
        "detection_methods": [
            "Detect Office spawning cmd.exe, powershell.exe, or uncommon processes",
            "Scan documents for `DDEAUTO`, `DDE`, or similar markers",
            "Alert on child process anomalies from Excel, Word, or Outlook"
        ],
        "apt": ["APT28", "TA505", "MuddyWater", "FIN7", "Sidewinder", "Gallmaker", "Cobalt Group"],
        "spl_query": [
            "index=win_logs EventCode=4688 ParentImage=*excel.exe OR *winword.exe CommandLine=*cmd.exe* OR *powershell.exe* \n| stats count by ParentImage, CommandLine, Account_Name",
            "index=endpoint_logs source=*\\AppData\\* sourcetype=file_upload file_name=\"*.doc\" OR file_name=\"*.xls\" content=\"*DDE*\" \n| stats count by file_name, user"
        ],
        "hunt_steps": [
            "Review Office-related process trees for signs of abuse (child process anomalies)",
            "Search for documents containing `DDEAUTO` or `cmd.exe` links",
            "Inspect endpoints for DDE-based file opens with triggered child processes"
        ],
        "expected_outcomes": [
            "Detection of Office documents used to invoke system commands via DDE",
            "Identification of phishing attempts bypassing macro filters"
        ],
        "false_positive": "Some legacy systems may use DDE for legitimate automation. Validate Office usage context and user intent.",
        "clearing_steps": [
            "Delete malicious Office or CSV files using DDE",
            "Kill spawned processes and remove payloads or scripts from temp directories",
            "Block DDE-based execution via registry edits or ASR enforcement"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference"
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1566", "example": "Phishing emails with DDE payloads"},
            {"tactic": "Execution", "technique": "T1059.003", "example": "Command execution via cmd triggered by Excel/Word"}
        ],
        "watchlist": [
            "Office apps launching command interpreters",
            "Files with DDE formulas opened by non-technical users"
        ],
        "enhancements": [
            "Apply ASR rules to block DDE-based child process creation",
            "Use Protected View to sandbox external documents",
            "Implement file content inspection for `DDEAUTO` or `=cmd|...` fields"
        ],
        "summary": "Dynamic Data Exchange (DDE) is a legacy IPC feature in Windows Office applications. It allows one application to execute commands in another and has been leveraged in phishing campaigns to execute code without macros.",
        "remediation": "Disable DDE through registry, enforce Protected View, and block Office-based child process creation via ASR policies.",
        "improvements": "Regularly scan documents for legacy execution strings, monitor Office activity for unusual child processes, and block file types vulnerable to DDE injection.",
        "mitre_version": "16.1"
    }
