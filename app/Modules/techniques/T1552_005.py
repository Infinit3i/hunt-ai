def get_content():
    return {
        "id": "T1552.005",
        "url_id": "T1552/005",
        "title": "Unsecured Credentials: Cloud Instance Metadata API",
        "description": "Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data.",
        "tags": ["cloud", "credentials", "metadata", "api", "ssrf", "aws", "azure", "gcp"],
        "tactic": "Credential Access",
        "protocol": "HTTP",
        "os": "IaaS",
        "tips": [
            "Restrict instance metadata access with firewalls and IAM controls.",
            "Use IMDSv2 on AWS and equivalent hardened metadata services in other cloud platforms.",
            "Audit application behavior to ensure metadata endpoints are not being accessed unnecessarily."
        ],
        "data_sources": "User Account",
        "log_sources": [
            {"type": "User Account", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Connections", "location": "http://169.254.169.254", "identify": "Unusual requests to instance metadata endpoint"},
            {"type": "Cloud Service", "location": "VPC Flow Logs / CloudTrail", "identify": "Access to metadata APIs or unusual IAM token usage"}
        ],
        "destination_artifacts": [
            {"type": "Cloud Service", "location": "CloudWatch / Logging solutions", "identify": "Requests containing metadata tokens or credentials used elsewhere"}
        ],
        "detection_methods": [
            "Monitor cloud logs for access to metadata IP (169.254.169.254)",
            "Detect metadata API queries from unauthorized services or users",
            "Correlate use of temporary credentials obtained via metadata API"
        ],
        "apt": [
            "Hildegard", "TeamTNT"
        ],
        "spl_query": [
            'index=cloud sourcetype="vpc:flowlogs" dest_ip="169.254.169.254"\n| stats count by src_ip, user, action',
            'index=cloud sourcetype="cloudtrail" eventName=Get*Metadata*\n| stats count by userIdentity.arn, sourceIPAddress, eventName'
        ],
        "hunt_steps": [
            "Identify all accesses to the metadata API from instances and correlate with known services.",
            "Review public-facing apps for SSRF vulnerabilities that could be used to reach metadata APIs.",
            "Look for credential use in logs following suspicious access to the metadata service."
        ],
        "expected_outcomes": [
            "Detection of adversary attempts to access or exploit metadata API",
            "Discovery of compromised temporary cloud credentials"
        ],
        "false_positive": "Legitimate applications querying metadata for configuration or identity. Validate expected behavior.",
        "clearing_steps": [
            "Rotate temporary credentials retrieved from metadata API",
            "Patch SSRF vulnerabilities or deploy SSRF protections like header enforcement",
            "Restrict access to metadata endpoints using IAM or network-level controls"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1190", "example": "Exploiting SSRF vulnerability to access metadata API"},
            {"tactic": "Defense Evasion", "technique": "T1556.004", "example": "Using temporary credentials obtained to blend in as legitimate user"}
        ],
        "watchlist": [
            "169.254.169.254", "IMDS", "metadata API", "SSRF", "GetInstanceIdentityDocument"
        ],
        "enhancements": [
            "Upgrade to IMDSv2 on AWS and require session-based tokens",
            "Deploy WAFs and SSRF protection for web-facing services",
            "Alert on unusual metadata endpoint traffic patterns"
        ],
        "summary": "Adversaries with access to a virtual machine may query the Cloud Instance Metadata API to retrieve sensitive credentials.",
        "remediation": "Use hardened metadata access (e.g., IMDSv2), restrict access, and prevent SSRF in externally facing applications.",
        "improvements": "Use cloud provider features to restrict access to metadata, enforce least privilege for IAM roles, and validate all outbound web requests from cloud apps.",
        "mitre_version": "16.1"
    }
