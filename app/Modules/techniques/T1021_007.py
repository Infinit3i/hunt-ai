def get_content():
    return {
        "id": "T1021.007",
        "url_id": "T1021/007",
        "title": "Remote Services: Cloud Services",
        "description": "Adversaries may use valid credentials to remotely access cloud services like IaaS, SaaS, or cloud APIs to perform management actions or access data.",
        "tags": ["cloud", "valid accounts", "federated identity", "cloud api", "azure", "gcp", "o365"],
        "tactic": "Lateral Movement",
        "protocol": "HTTPS (Cloud APIs, Web Console, CLI)",
        "os": "IaaS, Identity Provider, Office Suite, SaaS",
        "tips": [
            "Monitor for initial login and unexpected access from new locations/IPs in cloud audit logs.",
            "Track cloud CLI usage for administrative commands like `Connect-AZAccount` or `gcloud auth login`.",
            "Enforce MFA for all cloud accounts, especially administrative ones."
        ],
        "data_sources": "Logon Session",
        "log_sources": [
            {"type": "Logon Session", "source": "Cloud Audit Logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Logon Session", "location": "Microsoft 365 Unified Audit Log, Google Workspace Admin Audit", "identify": "login events via CLI or web console"},
            {"type": "Windows Defender Logs", "location": "C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History", "identify": "cloud login or token-based session"},
            {"type": "Environment Variables", "location": "User session or shell", "identify": "presence of cloud credentials or tokens"}
        ],
        "destination_artifacts": [
            {"type": "Cloud Storage", "location": "Blob Buckets, S3, Google Cloud Storage", "identify": "download or enumeration of sensitive files"},
            {"type": "Cloud Service", "location": "Azure AD, Google IAM, O365 Admin Portal", "identify": "role assignment, privilege escalation"},
            {"type": "Logon Session", "location": "Audit logs", "identify": "interactive login or service token use"}
        ],
        "detection_methods": [
            "Monitor cloud provider audit logs for login from unfamiliar geolocations or devices",
            "Detect abnormal use of cloud CLIs or access tokens",
            "Monitor for unexpected resource enumeration or configuration changes"
        ],
        "apt": ["Scattered Spider", "TELCO BPO Campaign"],
        "spl_query": [
            'index=o365 sourcetype="o365:azuread" Operation=UserLoggedIn \n| stats count by UserId, ClientIP, UserAgent',
            'index=gcp sourcetype="google:cloud:iam" protoPayload.methodName="google.iam.admin.v1.*" \n| table protoPayload.authenticationInfo.principalEmail, methodName',
            'index=azure sourcetype="azure:activity" \n| search OperationName="Connect-AzAccount" OR OperationName="Set-AzContext"'
        ],
        "hunt_steps": [
            "Query for use of cloud CLI commands initiating login",
            "Investigate interactive logins from abnormal locations",
            "Search for privilege escalations or role changes post-login"
        ],
        "expected_outcomes": [
            "Identify adversary use of cloud credentials to pivot to additional resources",
            "Detect unauthorized access to administrative cloud APIs or services",
            "Understand cloud lateral movement paths"
        ],
        "false_positive": "Cloud administrators often use CLI tools to authenticate; baseline known behavior to reduce noise.",
        "clearing_steps": [
            "Revoke compromised tokens with cloud identity provider",
            "Force logout sessions across cloud tenants",
            "Rotate all cloud-related access credentials and audit IAM roles"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1550.001", "example": "Use of application access token for CLI login"},
            {"tactic": "Discovery", "technique": "T1087", "example": "Query cloud directory for user and group enumeration"}
        ],
        "watchlist": [
            "Connect-AzAccount or gcloud login activity outside normal hours",
            "Login events without MFA from known admin accounts",
            "Access to sensitive storage buckets or Office 365 admin actions"
        ],
        "enhancements": [
            "Implement Conditional Access Policies in Azure AD or GCP IAM",
            "Enable real-time alerts for risky login behavior or CLI access",
            "Deploy Identity Protection tools (e.g., Azure Identity Protection, Google BeyondCorp)"
        ],
        "summary": "Adversaries may use cloud service access with valid credentials to laterally move, manage services, and extract data without needing local access to infrastructure.",
        "remediation": "Restrict access to cloud consoles and enforce least privilege. Monitor all authentication to cloud services and require MFA.",
        "improvements": "Enhance cloud security posture with continuous auditing, token expiration, and session timeout policies.",
        "mitre_version": "16.1"
    }
