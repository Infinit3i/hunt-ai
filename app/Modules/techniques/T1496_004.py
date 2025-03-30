def get_content():
    return {
        "id": "T1496.004",
        "url_id": "T1496/004",
        "title": "Resource Hijacking: Cloud Service Hijacking",
        "description": "Adversaries may leverage compromised software-as-a-service (SaaS) applications to complete resource-intensive tasks, which may impact hosted service availability.",
        "tags": ["impact", "saas", "cloud abuse", "email abuse", "llmjacking", "availability", "phishing"],
        "tactic": "Impact",
        "protocol": "",
        "os": "SaaS",
        "tips": [
            "Audit API usage from cloud messaging services like AWS SES, SNS, SendGrid, and Twilio.",
            "Monitor for spikes in outbound email/SMS volume.",
            "Set strict service quotas and alert thresholds for cloud application usage.",
            "Flag unauthorized enabling of cloud services or reverse proxies targeting AI endpoints."
        ],
        "data_sources": "Application Log, Cloud Service",
        "log_sources": [
            {"type": "Application Log", "source": "Application Log Content", "destination": ""},
            {"type": "Cloud Service", "source": "Cloud Service Modification", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Application Log", "location": "SaaS Dashboard", "identify": "Outbound messages initiated from compromised accounts"},
            {"type": "Cloud Service", "location": "AWS CloudTrail or equivalent", "identify": "Activation or configuration of messaging services like SES/SNS"},
            {"type": "Process List", "location": "Serverless Functions or CI/CD", "identify": "Automation scripts sending mass messages"},
            {"type": "Event Logs", "location": "Cloud audit logs", "identify": "Excessive API requests or spam sending indicators"}
        ],
        "destination_artifacts": [
            {"type": "Cloud Service", "location": "External recipients", "identify": "Mass emails or SMS from hijacked cloud identity"},
            {"type": "Network Connections", "location": "Reverse proxy endpoints", "identify": "Suspicious outbound traffic to AI service endpoints"}
        ],
        "detection_methods": [
            "Detect high-volume outbound messaging activity from low-volume accounts.",
            "Monitor service enablement or changes to cloud configuration (e.g., enabling SES, SNS).",
            "Alert on abnormal billing increases or quota usage spikes.",
            "Detect proxy configuration targeting cloud AI infrastructure."
        ],
        "apt": ["DangerDev"],
        "spl_query": [
            'index=cloud_logs source="aws.ses"\n| stats count by user_identity.arn\n| where count > 1000\n| sort -count',
            'index=cloudtrail eventName=PutConfigurationSetTrackingOptions OR eventName=SendEmail\n| stats count by sourceIPAddress',
            'index=cloud_logs\n| search message="LLM API" OR message="openai.com" OR message="reverse proxy"\n| stats count by user, source_ip'
        ],
        "hunt_steps": [
            "Identify unauthorized activations of cloud services (SES, SNS, Twilio).",
            "Review high-volume sending activity across cloud messaging APIs.",
            "Inspect for proxy infrastructure redirecting traffic to LLM endpoints.",
            "Audit cloud configuration changes over the last 30 days."
        ],
        "expected_outcomes": [
            "Detection of cloud service abuse for spam or LLM hijacking.",
            "Identification of compromised accounts or API keys.",
            "Attribution of cost spikes to specific malicious workloads."
        ],
        "false_positive": "Legitimate bulk notification services (e.g., marketing or transactional systems) may cause similar patterns. Confirm business intent and authorized API usage.",
        "clearing_steps": [
            "Revoke exposed API keys: aws ses delete-identity --identity spammer@example.com",
            "Reset credentials and apply MFA to compromised cloud accounts.",
            "Disable unused cloud messaging services (SES, SNS, SendGrid, etc).",
            "Audit and remove unauthorized proxy configurations or IAM roles.",
            "Set billing alerts for future anomalies."
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-resource-abuse"],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1078.004", "example": "Abuse of valid cloud credentials for SaaS service usage"},
            {"tactic": "Command and Control", "technique": "T1090.002", "example": "Use of reverse proxies to route traffic to cloud-hosted AI models"}
        ],
        "watchlist": [
            "Accounts sending bulk messages through cloud APIs",
            "Sudden activation of messaging services in previously unused regions",
            "LLM-related traffic routed via suspicious proxy infrastructure",
            "Unusual increases in monthly cloud billing reports"
        ],
        "enhancements": [
            "Set service control policies (SCPs) to restrict who can enable messaging services.",
            "Deploy anomaly detection for outbound API traffic.",
            "Log all reverse proxy and LLM traffic interactions for forensics."
        ],
        "summary": "Cloud Service Hijacking involves misuse of SaaS platforms—especially messaging or AI services—for unauthorized tasks such as spam distribution, phishing, or compute-intensive operations, leading to financial loss or service disruption.",
        "remediation": "Identify and disable hijacked services, revoke API keys, reset compromised credentials, and enforce usage restrictions.",
        "improvements": "Integrate cloud security posture monitoring (CSPM), set quotas, apply IAM least-privilege, and monitor service usage trends.",
        "mitre_version": "16.1"
    }
