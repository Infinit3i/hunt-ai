def get_content():
    return {
        "id": "T1137.003",
        "url_id": "T1137/003",
        "title": "Office Application Startup: Outlook Forms",
        "description": "Adversaries may abuse Microsoft Outlook custom forms for persistence. These forms are templates for emails and can contain code that executes upon opening Outlook or receiving a specially crafted message that uses the malicious form.",
        "tags": ["persistence", "outlook", "forms", "office", "vba", "custom form"],
        "tactic": "persistence",
        "protocol": "",
        "os": "Office Suite, Windows",
        "tips": [
            "Monitor for Outlook startup behavior that loads custom forms",
            "Use PowerShell auditing to detect unauthorized custom form injection",
            "Investigate Outlook rules or forms that deviate from enterprise policy"
        ],
        "data_sources": "Application Log: Application Log Content, Command: Command Execution, Process: Process Creation",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Outlook Form", "location": "Mailbox (Custom Form Library)", "identify": "Malicious form triggering code execution"},
            {"type": "Process", "location": "OUTLOOK.EXE", "identify": "Abnormal child processes or command execution"}
        ],
        "destination_artifacts": [
            {"type": "Payload", "location": "Mailbox or local Outlook storage", "identify": "Persisted script/code within form"},
            {"type": "Process", "location": "Office Suite", "identify": "Spawned process based on malicious form"}
        ],
        "detection_methods": [
            "Analyze Outlook custom forms using Microsoft’s script",
            "Detect unusual child process creation from OUTLOOK.EXE",
            "Check Outlook’s VBScript macro engine usage"
        ],
        "apt": [
            "Suspected usage by multiple phishing campaigns using persistence techniques in Outlook"
        ],
        "spl_query": [
            'index=sysmon EventCode=1 Image="*\\OUTLOOK.EXE" \n| transaction startswith=Image endswith=ParentImage',
            'index=o365 sourcetype="o365:exchange" Operation="New-InboxRule" \n| search Parameters="Custom Form"',
            'index=wineventlog Message="*Custom Form*" AND EventCode=3008'
        ],
        "hunt_steps": [
            "Run Microsoft’s script to extract all Outlook custom forms",
            "Analyze contents of forms for embedded script or command logic",
            "Trace any abnormal OUTLOOK.EXE process trees"
        ],
        "expected_outcomes": [
            "Persistence is achieved by form-based code execution on Outlook launch",
            "Form can be triggered remotely via email sent to target user",
            "Hard to detect via conventional AV as code is embedded within form data"
        ],
        "false_positive": "Custom Outlook forms are occasionally used in legitimate business processes. Verify contents of any form flagged as suspicious.",
        "clearing_steps": [
            "Remove malicious form from user’s mailbox or form library",
            "Reset Outlook to default templates",
            "Disable scripting support for Outlook forms via GPO"
        ],
        "mitre_mapping": [
            {"tactic": "persistence", "technique": "T1137", "example": "Custom Outlook form executing code upon Outlook launch"},
            {"tactic": "execution", "technique": "T1059.005", "example": "VBA script execution within custom Outlook form"},
            {"tactic": "initial-access", "technique": "T1566.001", "example": "Email delivering specially crafted message to trigger Outlook form"}
        ],
        "watchlist": [
            "Outlook startup loading custom forms",
            "Outlook spawning PowerShell or cmd unexpectedly",
            "Mailboxes with high number of custom forms stored"
        ],
        "enhancements": [
            "Disable custom forms via administrative templates",
            "Monitor Outlook logs for unusual interactions with forms",
            "Use Microsoft Defender for Office 365 to block script-based attacks"
        ],
        "summary": "Custom Outlook forms allow an attacker to persist code in a user's mailbox, executing on Outlook launch or upon receiving specially crafted emails.",
        "remediation": "Scan mailboxes for custom forms, remove unauthorized ones, and enforce policy to block form-based execution.",
        "improvements": "Implement form execution logging and PowerShell-based auditing on mail clients. Block VBScript in Outlook where possible.",
        "mitre_version": "16.1"
    }
