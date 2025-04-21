def get_content():
    return {
        "id": "T1564.008",
        "url_id": "T1564/008",
        "title": "Hide Artifacts: Email Hiding Rules",
        "description": "Adversaries may create or manipulate email rules to automatically move, delete, or mark messages in a way that hides evidence of compromise, including alerts, C2 responses, and replies to spearphishing emails. By targeting specific keywords or senders, these rules can prevent a user or security analyst from noticing key emails that could reveal the adversary's presence. This technique is especially effective during Business Email Compromise (BEC) operations and can be applied either per-user or across the organization via transport rules.",
        "tags": ["email rules", "BEC", "Exchange abuse", "New-InboxRule", "Set-InboxRule", "Office 365", "transport rules"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "Linux, Office Suite, Windows, macOS",
        "tips": [
            "Look for inbox rules created using PowerShell, especially via New-InboxRule or Set-InboxRule",
            "Check for keywords in rules such as 'malware', 'security', 'alert', 'phish'",
            "Review logs for modifications to message rules files on macOS"
        ],
        "data_sources": "Application Log, Command, File",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "Windows Event Logs or Office 365 Unified Audit Log", "identify": "Activity involving New-InboxRule or Set-InboxRule"},
            {"type": "Command", "location": "PowerShell History", "identify": "Abuse of email rule cmdlets"},
            {"type": "File", "location": "~/Library/Mail/VX/MailData/", "identify": "MacOS rule plist files: MessageRules.plist, SyncedRules.plist, etc."}
        ],
        "destination_artifacts": [
            {"type": "File", "location": "User mailbox folders", "identify": "Unusual placement of messages with security relevance"},
            {"type": "Application Log", "location": "Exchange MessageTrace or Security logs", "identify": "Missing messages or altered delivery"},
            {"type": "Command", "location": "Exchange Online PowerShell", "identify": "Transport rules created or altered via Get-TransportRule"}
        ],
        "detection_methods": [
            "Monitor mailbox rule creation events, especially ones involving keyword-based filtering",
            "Analyze Exchange audit logs for unexpected rule configurations",
            "Compare expected vs actual folder paths for known alerting email sources"
        ],
        "apt": [
            "FIN4", "Octo Tempest", "APT28"
        ],
        "spl_query": [
            "index=o365 sourcetype=o365:exchange \n| search Operation=New-InboxRule OR Operation=Set-InboxRule \n| stats count by UserId, Parameters",
            "index=osquery \n| search file_path LIKE '%MessageRules.plist' \n| stats count by file_path, modified_at, username",
            "index=wineventlog EventCode=4104 \n| search ScriptBlockText=*Set-InboxRule* OR *New-InboxRule* \n| stats count by UserName, ScriptBlockText"
        ],
        "hunt_steps": [
            "Search for PowerShell rule creation involving suspicious keywords or external sender conditions",
            "Inspect mailboxes for folder rules affecting delivery of security or admin messages",
            "Flag any newly created org-wide transport rules with filtering logic targeting security or IT terms"
        ],
        "expected_outcomes": [
            "Detection of rules that redirect, delete, or suppress key messages",
            "Identification of mailboxes where security alerts are hidden",
            "Correlation of adversary-controlled inboxes with BEC or C2 activity"
        ],
        "false_positive": "Legitimate email filtering and inbox rules exist across organizations. Focus on automation, keyword filters, and accounts with elevated privileges for triage.",
        "clearing_steps": [
            "Remove suspicious inbox and transport rules from user or Exchange configuration",
            "Force MFA reset and password changes for affected accounts",
            "Restore access to critical messages by reprocessing deleted or redirected mail"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1114.003", "example": "Hiding emails using rules within compromised mailbox"},
            {"tactic": "Collection", "technique": "T1114", "example": "Reading mailbox content and filtering out specific threads"}
        ],
        "watchlist": [
            "Users creating or modifying many inbox rules in a short time",
            "PowerShell activity involving message rule manipulation",
            "New transport rules filtering security content at the org level"
        ],
        "enhancements": [
            "Alert on keyword-matching rule creation across mailboxes",
            "Periodically export and audit rule sets across high-risk users",
            "Correlate mail delivery patterns with rule modifications"
        ],
        "summary": "Email hiding rules allow adversaries to conceal evidence of compromise by redirecting or deleting messages related to alerts, phishing attempts, or internal investigations. These rules may target subject lines, message bodies, or senders, and can delay detection significantly.",
        "remediation": "Remove manipulated inbox or transport rules, reprocess hidden messages, audit mailbox configurations, and revoke session tokens associated with suspicious rule changes.",
        "improvements": "Centralize rule logging and change control, enforce rule creation policies, and enable conditional access policies for Exchange rule cmdlets.",
        "mitre_version": "16.1"
    }
