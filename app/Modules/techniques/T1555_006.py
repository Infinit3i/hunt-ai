def get_content():
    return {
        "id": "T1555.006",
        "url_id": "1555/006",
        "title": "Credentials from Password Stores: Cloud Secrets Management Stores",
        "description": "Adversaries may acquire credentials from cloud-native secret management solutions such as AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and Terraform Vault. These services securely store API keys, passwords, and other sensitive credentials. Attackers with sufficient privileges in a cloud environment may extract secrets via API requests, gaining access to sensitive information and enabling further compromise.",
        "tags": ["Credential Access", "Cloud Secrets", "Secrets Management"],
        "tactic": "Credential Access",
        "protocol": "Cloud API Calls, IAM Access Controls",
        "os": ["IaaS"],
        "tips": [
            "Monitor API calls to secrets management services for unauthorized access.",
            "Detect usage of commands like 'aws secretsmanager get-secret-value', 'gcloud secrets describe', or 'az key vault secret show'.",
            "Restrict high-privilege cloud account permissions to prevent unauthorized access to secrets."
        ],
        "data_sources": "Cloud Service Enumeration, API Calls, IAM Logs",
        "log_sources": [
            {"type": "Cloud Service", "source": "Secrets Management API Logs", "destination": "Cloud Audit Logs"},
            {"type": "IAM", "source": "User Access Logs", "destination": "Cloud Security Logs"}
        ],
        "source_artifacts": [
            {"type": "API Call", "location": "Cloud Secrets Management Services", "identify": "Unauthorized Secret Access"}
        ],
        "destination_artifacts": [
            {"type": "Credentials", "location": "Cloud Storage", "identify": "Extracted API Keys or Secrets"}
        ],
        "detection_methods": [
            "Monitor cloud API logs for excessive or unexpected secret retrieval attempts.",
            "Detect unauthorized access patterns in cloud identity and access management (IAM) logs.",
            "Alert on unusual privilege escalation events related to secrets access."
        ],
        "apt": ["Scattered Spider", "ScarletEel"],
        "spl_query": [
            "index=cloud_logs event_name=get-secret-value OR event_name=describe-secrets | table _time, user, service, resource_name"
        ],
        "hunt_steps": [
            "Review cloud audit logs for unauthorized secrets access.",
            "Analyze IAM roles and permissions for privilege misuse.",
            "Investigate instances where secrets were accessed outside expected workflows."
        ],
        "expected_outcomes": [
            "Detection of unauthorized secret retrieval attempts.",
            "Identification of compromised cloud accounts accessing sensitive credentials."
        ],
        "false_positive": "Legitimate administrative access to cloud secrets for application deployment.",
        "clearing_steps": [
            "Revoke compromised cloud credentials and rotate secrets.",
            "Restrict IAM permissions for accessing cloud secrets managers.",
            "Investigate the source of unauthorized secrets retrieval."
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "Extract Credentials from Cloud Secrets Management Stores", "example": "An attacker retrieves API keys from AWS Secrets Manager."}
        ],
        "watchlist": ["Cloud accounts accessing multiple secrets in a short timeframe."],
        "enhancements": ["Enable real-time alerting on unauthorized cloud secrets access."],
        "summary": "Attackers may extract credentials from cloud-based secret management stores to facilitate unauthorized access. Monitoring API activity and IAM logs can help detect this technique.",
        "remediation": "Enforce strict access controls on cloud secrets and implement logging for all credential retrieval events.",
        "improvements": "Enhance monitoring for secrets access anomalies and enable multi-factor authentication (MFA) for privileged accounts."
    }