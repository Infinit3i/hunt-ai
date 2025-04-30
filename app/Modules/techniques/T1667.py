def get_content():
    return {
        "id": "T1667",
        "url_id": "T1667",
        "title": "Email Bombing",
        "description": "Adversaries may flood targeted email addresses with an overwhelming volume of messages, disrupting business operations and burying legitimate communications.",
        "tags": ["impact", "email", "denial of service", "spam", "Storm-1811"],
        "tactic": "impact",
        "protocol": "SMTP, IMAP, POP3",
        "os": "Linux, Windows, macOS, Office Suite",
        "tips": [
            "Monitor email volume spikes per recipient across short time windows.",
            "Enable DMARC, SPF, and DKIM for all outbound email domains.",
            "Correlate email surges with suspicious follow-up activities (e.g., vishing or credential phishing)."
        ],
        "data_sources": "Application Log, File, Network Traffic",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""},
            {"type": "Network Traffic", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "File", "location": "mail client folders", "identify": "Large number of .eml, .msg, or .tmp files created in a short timeframe"}
        ],
        "destination_artifacts": [
            {"type": "Network Traffic", "location": "mail server logs", "identify": "High-volume SMTP connections targeting a single recipient"}
        ],
        "detection_methods": [
            "Analyze time-series data for abnormal email traffic volume per recipient.",
            "Monitor excessive file creations with .eml, .msg, or .tmp extensions.",
            "Correlate network flows on mail ports (25, 465, 587) with flow anomalies."
        ],
        "apt": ["Storm-1811"],
        "spl_query": [
            "index=email_logs sourcetype=\"mail:log\"\n| timechart span=5m count by recipient_email\n| eventstats avg(count) as avg_count stdev(count) as std_dev by recipient_email\n| eval spike=if(count > avg_count + (3*std_dev), 1, 0)\n| search spike=1\n| table _time, recipient_email, count, avg_count, std_dev",
            "EventCode=11 (file_name=\".eml\" OR file_name=\".msg\" OR file_name=\"*.tmp\")\n| stats count avg(file_size) max(file_size) by user, file_path, process_name, _time\n| where count > 100 OR max(file_size) > 1000000\n| table _time, user, process_name, file_path, file_name, count, max(file_size)",
            "sourcetype=\"zeek:conn\" dest_port=25 OR dest_port=465 OR dest_port=587\n| stats count avg(bytes_in) by src_ip, dest_ip, dest_port, _time\n| eventstats avg(count) as avg_flows, stdev(count) as std_flows by dest_ip\n| eval anomaly=if(count > avg_flows + (2*std_flows), 1, 0)\n| search anomaly=1\n| table _time, src_ip, dest_ip, dest_port, count, avg_flows"
        ],
        "hunt_steps": [
            "Identify user accounts receiving high email volume.",
            "Inspect timestamps for email floods that coincide with helpdesk alerts or user complaints.",
            "Trace the source of email origin across registration forms or marketing campaigns."
        ],
        "expected_outcomes": [
            "Detection of adversary attempts to suppress legitimate email alerts or overwhelm recipient inboxes."
        ],
        "false_positive": "Mass email campaigns (newsletters, HR announcements) may produce similar artifacts. Confirm legitimacy with mail source headers.",
        "clearing_steps": [
            "Temporarily block sender IPs or domains contributing to the email flood.",
            "Quarantine affected mailboxes for analysis and perform header-based rule filtering.",
            "Audit web form submissions associated with the victim email address."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-email-phishing"
        ],
        "mitre_mapping": [
            {"tactic": "impact", "technique": "T1667", "example": "Email Bombing"},
            {"tactic": "credential-access", "technique": "T1598.002", "example": "Spearphishing Voice"}
        ],
        "watchlist": [
            "Sudden spikes in email volume to VIP or executive mailboxes",
            "Multiple messages from diverse IPs containing no actionable content"
        ],
        "enhancements": [
            "Deploy anomaly detection models based on per-user email flow baselines.",
            "Integrate with mail security gateways to throttle or drop excessive messages in real-time."
        ],
        "summary": "Email Bombing is a disruptive technique used to overwhelm recipients with junk messages, often to hide legitimate alerts or set up follow-on social engineering attacks.",
        "remediation": "Use anti-spam controls, SPF/DKIM/DMARC enforcement, and rate-limiting to reduce exposure.",
        "improvements": "Include x-header tagging for all marketing email and enable security automation to respond to volumetric anomalies.",
        "mitre_version": "17.0"
    }