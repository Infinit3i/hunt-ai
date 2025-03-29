def get_content():
    return {
        "id": "T1221",
        "url_id": "T1221",
        "title": "Template Injection",
        "description": "Adversaries may create or modify references in user document templates to conceal malicious code or force authentication attempts. Documents may use embedded or remote template references to load malicious payloads upon opening, often bypassing static detection.",
        "tags": ["template injection", "remote template", "docx", "rtf", "SMB phishing", "forced authentication", "defense evasion"],
        "tactic": "Defense Evasion",
        "protocol": "HTTP, SMB, HTTPS",
        "os": "Windows",
        "tips": [
            "Alert on Office or RTF documents attempting to connect to external URLs on open.",
            "Detect network connections initiated by Office apps (e.g., winword.exe) at document load time.",
            "Scan for RTF documents with unusual \\template control words referencing URLs."
        ],
        "data_sources": "Network Traffic, Process",
        "log_sources": [
            {"type": "Network Traffic", "source": "Network Sensor", "destination": ""},
            {"type": "Process", "source": "Sysmon", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Connections", "location": "", "identify": "External connection initiated by Office or RTF document viewer"},
            {"type": "Prefetch Files", "location": "C:\\Windows\\Prefetch", "identify": "WINWORD.EXE or EXCEL.EXE used during execution of payload"}
        ],
        "destination_artifacts": [],
        "detection_methods": [
            "Monitor for Office processes initiating unexpected network connections",
            "Scan RTFs for \\template fields with embedded HTTP/HTTPS/SMB paths",
            "Alert on documents with embedded XML parts referencing external templates"
        ],
        "apt": [
            "Lazarus", "Gamaredon", "Sofacy", "Tropic Trooper", "Frankenstein", "Confucius", "Actinium", "IRON TILDEN", "Chaes", "Inception"
        ],
        "spl_query": [
            "index=network sourcetype=zeek* OR sourcetype=suricata* dest_port=80 OR dest_port=443\n| search uri_path=\"*.docx\" OR uri_path=\"*.rtf\"\n| stats count by uri_path, src_ip, dest_ip",
            "index=sysmon EventCode=1 Image=*\\winword.exe OR *\\excel.exe\n| search CommandLine=\"http*\" OR CommandLine=\"\\\\*\"\n| stats count by CommandLine, User, ParentImage"
        ],
        "hunt_steps": [
            "Review Office document traffic for URLs fetched at open time",
            "Scan incoming RTF files for abnormal \\template strings referencing web or SMB resources",
            "Use static file analyzers to extract and inspect OOXML relationships or RTF control words"
        ],
        "expected_outcomes": [
            "Detection of malicious payloads fetched via remote templates",
            "Identification of forced authentication attempts via SMB/HTTPS URLs in templates",
            "Visibility into pre-execution payload delivery using legitimate Office mechanics"
        ],
        "false_positive": "Legitimate corporate templates hosted internally may use similar mechanisms. Validate URLs, domains, and timing of the access.",
        "clearing_steps": [
            "Delete the offending document (.docx/.rtf/.xlsx)",
            "Remove cached copies or downloaded payloads from %TEMP%",
            "Purge recent file lists and verify registry keys under HKCU\\Software\\Microsoft\\Office for persistent template links"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-malware"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566", "example": "Document delivered via phishing containing remote template reference"},
            {"tactic": "Credential Access", "technique": "T1187", "example": "SMB-based forced authentication triggered by opening the document"},
            {"tactic": "Defense Evasion", "technique": "T1221", "example": "Payload stored remotely, avoiding macro or script indicators"}
        ],
        "watchlist": [
            "Office processes initiating outbound SMB/HTTP on open",
            "Unusual .docx/.rtf/.pptx documents with embedded remote references",
            "RTF files with control word \\template http or \\template \\u"
        ],
        "enhancements": [
            "Enable logging for Office template loading via Group Policy or Defender ASR rules",
            "Deploy email content inspection tools to scan embedded URLs in OOXML and RTF",
            "Use sandbox detonation to monitor network traffic and behavior during document opening"
        ],
        "summary": "Template Injection leverages remote references in Office or RTF document templates to fetch and execute payloads without embedding code locally. These payloads may initiate forced authentication or bypass static detection entirely.",
        "remediation": "Block external template fetching via GPO. Use endpoint protection and email inspection tools to detect and quarantine suspicious documents. Restrict outbound SMB traffic.",
        "improvements": "Add Office telemetry and URL access correlation for high-fidelity detection. Monitor \\template indicators in RTFs and inspect OOXML relationship tags.",
        "mitre_version": "16.1"
    }
