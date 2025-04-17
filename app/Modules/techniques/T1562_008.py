def get_content():
    return {
        "id": "T1562.008",
        "url_id": "T1562/008",
        "title": "Impair Defenses: Disable or Modify Cloud Logs",
        "description": "An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection. Cloud environments allow for collection and analysis of audit and application logs that provide insight into user activity. If an adversary has sufficient permissions, they may disable or tamper with logging to conceal malicious actions.\n\nFor example, in AWS, adversaries may disable CloudTrail or CloudWatch integrations. They might also remove SNS topics, disable multi-region logging, or alter validation/encryption settings for logs. In Office 365, adversaries may disable mail activity logging for specific users using `Set-MailboxAuditBypassAssociation`, downgrade licenses to remove advanced auditing, or disable relevant settings. These actions hinder detection and forensic investigation capabilities.",
        "tags": ["cloud", "logging", "audit", "cloudtrail", "azure", "gcp", "m365", "evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "IaaS, Identity Provider, Office Suite, SaaS",
        "tips": [
            "Continuously monitor for log stream interruptions or unexpected deletions of logging configurations.",
            "Use alerting for critical logging API calls such as `StopLogging` or `UpdateSink`.",
            "Enforce strict IAM roles and monitor for privilege escalation events that could lead to logging disruptions."
        ],
        "data_sources": "Cloud Service, User Account",
        "log_sources": [
            {"type": "Cloud Service", "source": "", "destination": ""},
            {"type": "User Account", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Cloud Logging Events", "location": "AWS CloudTrail, Azure Monitor, GCP Audit Logs", "identify": "Disable or modify logging behavior"},
            {"type": "IAM Activity", "location": "IAM role or user privilege change logs", "identify": "Permissions sufficient to stop logs"},
            {"type": "CLI/API Calls", "location": "CloudShell, awscli, azcli, gcloud", "identify": "Execution of StopLogging/DeleteTrail/UpdateSink"}
        ],
        "destination_artifacts": [
            {"type": "Log Storage", "location": "S3 buckets, Azure Blob Storage, GCP Cloud Storage", "identify": "Missing or incomplete logs"},
            {"type": "SNS/Notification Hooks", "location": "AWS SNS Topics", "identify": "Unexpectedly deleted or removed"},
            {"type": "Audit Trail", "location": "Log retention settings or versioning policies", "identify": "Tampered validation or encryption controls"}
        ],
        "detection_methods": [
            "Monitor for API calls like `StopLogging`, `DeleteTrail`, `UpdateSink`, or `az monitor diagnostic-settings delete`",
            "Alert on changes to logging destinations or removal of audit policies",
            "Track license changes in M365 that reduce audit capabilities (e.g., E5 → E3)",
            "Correlate sudden logging drop-offs with account modifications"
        ],
        "apt": ["APT29"],
        "spl_query": [
            "index=aws_cloudtrail eventName IN (StopLogging, DeleteTrail) \n| stats count by userIdentity.arn, sourceIPAddress, eventTime",
            "index=gcp_auditlog protoPayload.methodName=\"google.logging.v2.ConfigServiceV2.UpdateSink\" \n| stats count by resource.labels.project_id, authenticationInfo.principalEmail",
            "index=azure_logs operationName=\"Microsoft.Insights/diagnosticSettings/delete\" \n| stats count by identity, resourceGroup"
        ],
        "hunt_steps": [
            "Look for users making `StopLogging` or related calls across cloud logs",
            "Review any changes in logging sink configuration or loss of multi-region logging",
            "Search for deleted or disabled audit trail settings for mailboxes in M365",
            "Identify API calls to downgrade or alter license tiers tied to audit capabilities"
        ],
        "expected_outcomes": [
            "Detection of unauthorized attempts to disrupt cloud log visibility",
            "Identification of IAM role misuse to suppress logs",
            "Alerting on cloud-native API events that indicate log tampering or suppression"
        ],
        "false_positive": "Legitimate administrative maintenance actions may disable logging temporarily. Review time of day, initiator, and context before escalation.",
        "clearing_steps": [
            "Re-enable logging pipelines using cloud provider tools (e.g., `aws cloudtrail start-logging`)",
            "Audit and restore removed diagnostic settings or sinks",
            "Reassign or revalidate IAM roles and permissions affecting log visibility",
            "Restore log storage redundancy, encryption, and notification settings"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562.008", "example": "Using StopLogging or Set-MailboxAuditBypassAssociation to disable audit trails"}
        ],
        "watchlist": [
            "Recurrent execution of disable-logging commands by unrecognized users",
            "Downgrades from E5 to E3 licensing in Microsoft 365 environments",
            "Drop in expected logging volume or missing multi-region logs"
        ],
        "enhancements": [
            "Enable log integrity validation and immutability settings where possible",
            "Configure canary logs that generate alerts if not received",
            "Deploy anomaly detection on log activity patterns for suppression attempts"
        ],
        "summary": "T1562.008 captures adversary behavior aimed at disrupting logging and monitoring in cloud environments. By disabling or modifying log collection, attackers evade detection and complicate forensic analysis.",
        "remediation": "Enforce least privilege IAM policies, monitor all changes to log configurations, and implement immutability and alerts on logging pipelines.",
        "improvements": "Automate alerts for critical API calls related to logging, and continuously validate the presence and functionality of audit logs across all cloud environments.",
        "mitre_version": "16.1"
    }
