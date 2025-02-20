def get_content():
    """
    Returns structured content for the User Execution (T1204) technique.
    """
    return {
        "id": "T1204",
        "url_id": "T1204",
        "title": "User Execution",
        "tactic": "Execution",
        "data_sources": "Windows Event Logs, Process Monitoring, Email Logs, Web Proxy Logs, EDR Logs",
        "protocol": "HTTP/HTTPS, SMB, Email (SMTP, IMAP, POP3)",
        "os": "Windows, Linux, macOS",
        "objective": "Adversaries rely on users to manually execute malicious code, such as opening infected files, clicking on links, or running scripts.",
        "scope": "Monitor user activity for execution of suspicious files, scripts, or links triggered by social engineering.",
        "threat_model": "Attackers trick users into executing malware through phishing emails, fake downloads, or infected attachments, leading to system compromise.",
        "hypothesis": [
            "Are users executing malicious attachments or links from phishing emails?",
            "Are employees downloading and running files from untrusted sources?",
            "Are macro-enabled Office documents, scripts, or trojanized installers being executed?"
        ],
        "tips": [
            "Monitor process execution for suspicious scripts and executables (`.js`, `.vbs`, `.bat`, `.exe`).",
            "Investigate email attachments and web downloads for potential malware.",
            "Correlate user activity with threat intelligence to identify known malicious domains or senders."
        ],
        "log_sources": [
            {"type": "Process Execution Logs", "source": "Windows Event Logs (4688), Sysmon (Event ID 1, 10)"},
            {"type": "Email Security Logs", "source": "Microsoft Exchange, Proofpoint, Barracuda, Mimecast"},
            {"type": "Web Proxy Logs", "source": "Bluecoat, Zscaler, Netskope, Cisco Umbrella"},
            {"type": "EDR Logs", "source": "CrowdStrike, Defender ATP, SentinelOne"}
        ],
        "source_artifacts": [
            {"type": "Email Attachments", "location": "User inbox", "identify": "Suspicious file extensions (`.docm`, `.xlsm`, `.zip`, `.iso`, `.lnk`)"},
            {"type": "Web Downloads", "location": "Browser cache and download history", "identify": "Executable files from non-corporate sources"}
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "C:\\Users\\Public\\Downloads", "identify": "Malware executed from user directories"},
            {"type": "Registry Keys", "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "identify": "Persistence mechanisms set by user-executed malware"}
        ],
        "detection_methods": [
            "Monitor process execution triggered by user actions (e.g., opening email attachments).",
            "Detect execution of script-based malware delivered via phishing.",
            "Analyze web proxy logs for downloads of malicious file types."
        ],
        "apt": ["G0016", "G0032"],
        "spl_query": [
            "index=windows EventCode=4688 (Image='*winword.exe' OR Image='*excel.exe' OR Image='*outlook.exe') (CommandLine='*powershell*' OR CommandLine='*cmd.exe*') | table Time, Process, ParentProcess, Command",
            "index=proxy_logs http_method=GET (http_uri='*.exe' OR http_uri='*.js' OR http_uri='*.vbs') | table Time, src_ip, dest_domain, http_uri"
        ],
        "hunt_steps": [
            "Analyze execution of Office macros and scripting engines (`wscript.exe`, `cscript.exe`).",
            "Correlate phishing email logs with endpoint execution events.",
            "Identify downloaded executables that were executed by users."
        ],
        "expected_outcomes": [
            "Malicious user-executed scripts or files detected and contained.",
            "No evidence of compromise, refining detection baselines."
        ],
        "false_positive": "Legitimate users may download and execute applications for business purposes.",
        "clearing_steps": [
            "Quarantine and delete identified malware or suspicious scripts.",
            "Educate users on phishing threats and social engineering risks.",
            "Update SIEM rules to refine detection of user-executed threats."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1566.001 (Spearphishing Attachment)", "example": "User executes a macro-enabled document from a phishing email."}
        ],
        "watchlist": [
            "Monitor execution of macros, scripting interpreters, and LOLBins.",
            "Detect unusual file execution from user directories."
        ],
        "enhancements": [
            "Enable attack surface reduction rules to block macro-based malware.",
            "Implement browser protections against malicious downloads.",
            "Deploy endpoint protection to detect and block unauthorized script execution."
        ],
        "summary": "Adversaries rely on user interaction to execute malicious payloads, often delivered via phishing emails, drive-by downloads, or social engineering.",
        "remediation": "Block execution of untrusted scripts, quarantine malicious files, and educate users on security best practices.",
        "improvements": "Enhance email security, restrict script execution via Group Policy, and improve behavioral detection models."
    }