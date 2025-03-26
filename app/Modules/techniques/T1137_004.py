def get_content():
    return {
        "id": "T1137.004",
        "url_id": "T1137/004",
        "title": "Office Application Startup: Outlook Home Page",
        "description": "Adversaries may abuse Microsoft Outlook’s Home Page feature to persist on a system. This legacy feature allows a web page (internal or external) to be embedded in a folder view within Outlook. When a user opens the affected folder, the embedded web page is loaded and can be crafted to execute malicious code.",
        "tags": ["persistence", "outlook", "homepage", "office", "legacy feature", "vba", "html injection"],
        "tactic": "persistence",
        "protocol": "",
        "os": "Office Suite, Windows",
        "tips": [
            "Disable the Outlook Home Page feature via Group Policy",
            "Audit folder properties within mailboxes to detect homepage URLs",
            "Monitor for abnormal child processes spawned by OUTLOOK.EXE"
        ],
        "data_sources": "Application Log: Application Log Content, Command: Command Execution, Process: Process Creation",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Outlook Folder Property", "location": "User Mailbox", "identify": "Home Page URL with embedded script or malicious link"}
        ],
        "destination_artifacts": [
            {"type": "Process", "location": "OUTLOOK.EXE", "identify": "Unexpected child processes or script execution"},
            {"type": "Web Page", "location": "Remote Server or Embedded HTML", "identify": "Malicious code execution on folder access"}
        ],
        "detection_methods": [
            "Use Microsoft script to enumerate and audit Outlook folders with homepage settings",
            "Monitor OUTLOOK.EXE for abnormal command-line behavior or unusual child processes",
            "Inspect folder properties for URLs pointing to unexpected or untrusted web content"
        ],
        "apt": [
            "Seen in post-exploitation toolsets such as Ruler, which target Outlook features for persistence"
        ],
        "spl_query": [
            'index=o365 sourcetype="o365:exchange" "HomePage" OR "homepageurl"',
            'index=sysmon EventCode=1 Image="*\\OUTLOOK.EXE" | transaction startswith=Image endswith=ParentImage',
            'index=wineventlog Message="Outlook Home Page*"'
        ],
        "hunt_steps": [
            "Run Microsoft script to collect mailbox Home Page settings",
            "Inspect any Home Page pointing to external or suspicious URLs",
            "Correlate those settings with OUTLOOK.EXE startup activity"
        ],
        "expected_outcomes": [
            "Persistence achieved via HTML code loading at Outlook folder view",
            "Execution occurs when user interacts with a specific Outlook folder",
            "Hard to detect unless mailbox configuration is audited"
        ],
        "false_positive": "Custom homepage usage in Outlook is rare and mostly legacy. False positives are unlikely unless intentionally configured by IT.",
        "clearing_steps": [
            "Remove Home Page property from affected Outlook folders",
            "Deploy Group Policy Object (GPO) to disable Home Page functionality in Outlook",
            "Reset affected Outlook profile"
        ],
        "mitre_mapping": [
            {"tactic": "persistence", "technique": "T1137", "example": "Outlook Home Page property abused to execute embedded HTML/JavaScript"},
            {"tactic": "execution", "technique": "T1059.007", "example": "Malicious JavaScript execution via Outlook embedded web page"}
        ],
        "watchlist": [
            "Outlook processes accessing web content from within the mailbox",
            "Abnormal startup behavior associated with OUTLOOK.EXE",
            "External HTTP/HTTPS traffic generated immediately after opening Outlook"
        ],
        "enhancements": [
            "Block use of Home Page feature via registry and GPO",
            "Inspect mailbox folder settings at regular intervals",
            "Integrate mailbox audit logs into SIEM for anomaly detection"
        ],
        "summary": "This technique leverages a legacy Outlook feature to load malicious HTML content embedded in a folder, enabling stealthy and persistent execution when Outlook folders are accessed.",
        "remediation": "Audit and remove homepage settings from all Outlook folders. Disable the feature across the environment through GPO.",
        "improvements": "Automate scanning for homepage fields in Exchange mailboxes. Disable unnecessary legacy features like Outlook Home Page via policy.",
        "mitre_version": "16.1"
    }
