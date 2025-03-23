def get_content():
    return {
        "id": "T1585.003",
        "url_id": "T1585/003",
        "title": "Establish Accounts: Cloud Accounts",
        "description": "Adversaries may create accounts with cloud providers that can be used during targeting. Adversaries can use cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, MEGA, Microsoft OneDrive, or AWS S3 buckets for Exfiltration to Cloud Storage or to Upload Tools.",
        "tags": ["cloud", "exfiltration", "infrastructure", "resource development"],
        "tactic": "Resource Development",
        "protocol": "",
        "os": "PRE",
        "tips": [
            "Monitor access to known cloud services that are not commonly used within your organization.",
            "Track anomalous activity associated with cloud infrastructure providers from unexpected regions.",
            "Use DLP solutions to monitor upload activity to cloud storage services."
        ],
        "data_sources": "",
        "log_sources": [],
        "source_artifacts": [
            {"type": "Cloud Account Creation", "location": "Cloud Service Provider", "identify": "Account created with disposable or suspicious email"}
        ],
        "destination_artifacts": [
            {"type": "Cloud Service Usage", "location": "Cloud Platform", "identify": "Tools uploaded to new cloud storage buckets"}
        ],
        "detection_methods": [
            "Monitor access and usage of cloud service APIs",
            "Detect abnormal cloud bucket creation or object uploads"
        ],
        "apt": [],
        "spl_query": [
            'index=proxy OR index=cloud sourcetype=cloudstorage_access\n| search service IN ("dropbox", "mega", "onedrive", "s3")\n| stats count by user, action, service'
        ],
        "hunt_steps": [
            "Identify new accounts accessing cloud infrastructure services",
            "Review recent cloud bucket creation logs",
            "Check for unusual data upload patterns to cloud storage"
        ],
        "expected_outcomes": [
            "Detection of adversary-owned cloud accounts used in operations",
            "Prevention or mitigation of cloud-based exfiltration channels"
        ],
        "false_positive": "Legitimate use of personal cloud storage by employees for non-malicious reasons.",
        "clearing_steps": [
            "Block access to known malicious cloud services",
            "Revoke credentials used to access unauthorized cloud accounts",
            "Remove uploaded tools from attacker-controlled cloud buckets"
        ],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1567.002", "example": "Data uploaded to MEGA via attacker-created cloud account"},
            {"tactic": "Resource Development", "technique": "T1583.003", "example": "Virtual Private Server created using malicious cloud account"}
        ],
        "watchlist": [
            "New bucket creations across providers (AWS S3, Azure Blob, GCP Storage)",
            "New user agents tied to cloud CLI tools"
        ],
        "enhancements": [
            "Integrate cloud audit logs with SIEM",
            "Alert on cloud account creation from suspicious IP ranges or unusual email domains"
        ],
        "summary": "Adversaries may create cloud accounts to host tools, exfiltrate data, or stage operations without needing to manage their own infrastructure directly.",
        "remediation": "Review and block access to unknown or unauthorized cloud accounts. Work with cloud service providers to suspend malicious accounts when discovered.",
        "improvements": "Implement least-privilege policies and user behavior monitoring for cloud activity. Use CASBs to monitor data flows to cloud platforms.",
        "mitre_version": "16.1"
    }
