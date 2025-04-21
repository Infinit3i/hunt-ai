def get_content():
    return {
        "id": "T1567.004",
        "url_id": "T1567.004",
        "title": "Exfiltration Over Web Service: Exfiltration Over Webhook",
        "description": "Adversaries may exfiltrate data via webhook endpoints instead of traditional C2 channels. Webhooks are commonly used in services like Discord, Slack, GitHub, Trello, or Jira, allowing servers to push data to endpoints via HTTP/S. \n\nAdversaries may abuse these mechanisms by posting data directly to webhook URLs or linking their own SaaS environments to victim-owned services for automated, repeated exfiltration. Since webhook traffic often utilizes HTTPS, it may bypass basic detection mechanisms and blend in with normal SaaS activity.\n\nThis method may allow exfiltration of emails, documents, tickets, chat messages, and more while evading inspection due to encryption and the use of trusted SaaS platforms.",
        "tags": ["exfiltration", "webhook", "discord", "slack", "saas", "https", "obfuscation", "exfil-over-web"],
        "tactic": "Exfiltration",
        "protocol": "HTTPS, HTTP",
        "os": "Linux, Windows, macOS, Office Suite, SaaS",
        "tips": [
            "Look for outbound HTTP POSTs to known webhook endpoint patterns (e.g., `discord.com/api/webhooks/`, `hooks.slack.com`).",
            "Monitor SaaS integrations to detect unexpected webhook configurations.",
            "Review webhook audit logs from services like GitHub, Jira, and Trello."
        ],
        "data_sources": "Application Log, Command Execution, File Access, Network Traffic Content, Network Traffic Flow",
        "log_sources": [
            {"type": "Network Traffic", "source": "Proxy Logs, Firewall Logs, Packet Capture", "destination": ""},
            {"type": "Application Log", "source": "GitHub Audit Logs, Slack Admin Logs, SaaS provider logs", "destination": ""},
            {"type": "Command Execution", "source": "EDR, PowerShell Logs, Sysmon Event ID 1", "destination": ""},
            {"type": "File Access", "source": "EDR, DLP Solutions", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Staged Data", "location": "Local filesystem or memory", "identify": "Data packaged prior to webhook POST"},
            {"type": "Webhook Configuration", "location": "SaaS services (GitHub, Jira)", "identify": "Suspicious webhook pointing to non-org domain"}
        ],
        "destination_artifacts": [
            {"type": "Webhook Endpoint", "location": "Adversary-controlled SaaS or public service", "identify": "Receives staged data"},
            {"type": "Network Traffic", "location": "Outbound HTTPS POST", "identify": "Outbound data over webhook URL"}
        ],
        "detection_methods": [
            "Inspect outbound HTTPS traffic for webhook domains not sanctioned by the organization.",
            "Monitor for POST requests carrying large payloads to webhook endpoints.",
            "Alert on new webhook registrations in SaaS environments not tied to approved integrations."
        ],
        "apt": [],
        "spl_query": [
            "index=proxy OR index=network \n| search uri_path=\"/api/webhooks/\" OR uri_path=\"/hooks/\" \n| stats count by src_ip, dest_ip, uri_path"
        ],
        "hunt_steps": [
            "Identify outbound HTTP/S traffic with URI paths resembling webhook endpoints.",
            "Cross-reference webhook destinations with known-good SaaS integrations.",
            "Review POST payload sizes and frequency from hosts not expected to send data externally.",
            "Search for patterns suggesting file staging and transmission.",
            "Check for automation from command-line tools or scripts using curl, PowerShell, or Python."
        ],
        "expected_outcomes": [
            "Webhook Exfiltration Detected: Block endpoint, investigate source host, and check other SaaS integrations.",
            "No Malicious Activity Found: Update detection signatures and refine webhook baselines."
        ],
        "false_positive": "Legitimate automation tools and SaaS integrations (e.g., CI/CD pipelines) may use webhooks frequently. Validate against approved service configurations.",
        "clearing_steps": [
            "Disable or remove unauthorized webhook from SaaS service settings.",
            "Revoke access tokens or credentials associated with the compromised endpoint.",
            "Block or sinkhole malicious webhook URLs via proxy or firewall rules."
        ],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1567.004 (Exfiltration Over Webhook)", "example": "Adversary uses Discord webhook to receive sensitive documents."},
            {"tactic": "Command and Control", "technique": "T1102.002 (Web Service: Bidirectional Communication)", "example": "Adversary posts data to a webhook and uses the response for coordination."}
        ],
        "watchlist": [
            "Track outbound webhook traffic to new or unapproved domains.",
            "Alert on webhook traffic outside business hours or from unmonitored hosts.",
            "Monitor SaaS audit logs for new webhook registrations."
        ],
        "enhancements": [
            "Create allowlists for trusted webhook endpoints.",
            "Enable webhook monitoring and alerting in GitHub, Slack, and Jira.",
            "Use DLP tools to prevent data exfiltration via web-based methods."
        ],
        "summary": "Webhook-based exfiltration allows adversaries to bypass typical detection by leveraging SaaS-integrated mechanisms and encrypted HTTP traffic. Monitoring webhook activity is essential to detect and disrupt this technique.",
        "remediation": "Revoke malicious webhook endpoints, block domains, and audit SaaS integrations for unauthorized access.",
        "improvements": "Enhance SaaS telemetry visibility, enforce webhook registration reviews, and deploy anomaly detection for outbound web traffic.",
        "mitre_version": "16.1"
    }
