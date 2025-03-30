def get_content():
    return {
        "id": "T1496.003",
        "url_id": "T1496/003",
        "title": "Resource Hijacking: SMS Pumping",
        "description": "Adversaries may leverage messaging services for SMS pumping, which may impact system and/or hosted service availability.",
        "tags": ["impact", "sms fraud", "telecom abuse", "otp abuse", "availability", "cloud", "aws", "twilio"],
        "tactic": "Impact",
        "protocol": "",
        "os": "SaaS",
        "tips": [
            "Monitor SMS sending volume by user and recipient region.",
            "Flag excessive OTP requests from the same source IP.",
            "Implement rate-limiting and CAPTCHA protection on public-facing forms.",
            "Integrate telecom fraud detection APIs or services to flag known pumping activity."
        ],
        "data_sources": "Application Log",
        "log_sources": [
            {"type": "Application Log", "source": "Application Log Content", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Event Logs", "location": "SMS Gateway or Twilio logs", "identify": "High volume of outbound SMS requests to foreign or uncommon numbers"},
            {"type": "Application Log", "location": "Web backend / OTP form", "identify": "Repeated form submissions from the same IP or region"},
            {"type": "Windows Defender Logs", "location": "Defender ATP (optional SaaS insight)", "identify": "Alerts related to automated abuse of messaging APIs"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "SMS provider API endpoints", "identify": "Burst of API calls targeting Twilio, AWS SNS, etc."},
            {"type": "Application Log", "location": "Cloud Messaging Service Logs", "identify": "Surge in transaction volume to unexpected regions"}
        ],
        "detection_methods": [
            "Detect excessive SMS send requests from single users or IPs.",
            "Correlate patterns of OTP abuse across multiple accounts.",
            "Alert on message delivery to unusual carrier networks or countries.",
            "Monitor for recurring use of disposable or premium rate numbers."
        ],
        "apt": [],
        "spl_query": [
            'index=application_logs sourcetype="sms_gateway"\n| stats count by user_id, phone_number_region\n| where count > 100\n| sort -count',
            'index=web_logs\n| search url="/send_otp" OR url="/verify"\n| stats count by client_ip\n| where count > 50',
            'index=aws_logs source="sns"\n| stats count by destination_number_prefix\n| where count > 200'
        ],
        "hunt_steps": [
            "Identify accounts or IPs generating high volume of OTP/SMS sends.",
            "Investigate recipient numbers for signs of SMS pumping (e.g., premium-rate or international ranges).",
            "Audit logs for rapid, repeated requests to verification or contact forms.",
            "Review billing spikes from SMS providers and correlate with user activity."
        ],
        "expected_outcomes": [
            "Detection of accounts or IPs abusing SMS APIs for pumping fraud.",
            "Visibility into abused endpoints or public forms.",
            "Prevention of further financial loss through rate limiting and controls."
        ],
        "false_positive": "High-volume legitimate usage from password recovery or customer authentication may resemble pumping activity. Cross-reference known user behavior and support logs.",
        "clearing_steps": [
            "Block or throttle API access from abusive IPs: iptables -A INPUT -s <IP> -j DROP",
            "Disable affected user accounts pending review.",
            "Add CAPTCHA or 2FA challenge to high-risk forms.",
            "Set messaging API quotas or thresholds for user-based usage."
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-resource-abuse"],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1110.001", "example": "Abuse of OTP fields in login forms"},
            {"tactic": "Collection", "technique": "T1119", "example": "Collection of funds via SMS payment fraud"}
        ],
        "watchlist": [
            "Outbound SMS requests to high-cost or foreign numbers",
            "Excessive OTP requests from public web forms",
            "Billing alerts from Twilio, AWS SNS, or other providers",
            "Anomalous traffic spikes from known abused endpoints"
        ],
        "enhancements": [
            "Implement rate limits and IP-based throttling for all messaging endpoints.",
            "Use telecom validation services to flag suspicious numbers in real-time.",
            "Log all SMS request metadata for retrospective analysis and correlation."
        ],
        "summary": "SMS Pumping is a form of telecom fraud in which adversaries exploit SMS APIs, often through public forms, to generate traffic toward a set of phone numbers they profit from, leading to financial loss and potential service disruption.",
        "remediation": "Identify abusive behavior, block originating sources, apply quotas and rate limits, and implement friction in public forms.",
        "improvements": "Deploy automated fraud detection for messaging usage, analyze geographic traffic patterns, and implement CAPTCHA for all messaging triggers.",
        "mitre_version": "16.1"
    }
