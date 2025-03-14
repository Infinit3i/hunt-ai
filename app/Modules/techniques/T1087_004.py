def get_content():
    return {
        "id": "T1087.004",  # Tactic Technique ID
        "url_id": "1087/004",  # URL segment for technique reference
        "title": "Account Discovery: Cloud Account",  # Name of the attack technique
        "description": (
            "Adversaries may attempt to get a listing of cloud accounts. Cloud accounts are those created and configured "
            "by an organization for use by users, remote support, services, or for administration of resources within a "
            "cloud service provider or SaaS application. With authenticated access there are several tools that can be "
            "used to find accounts. The <code>Get-MsolRoleMember</code> PowerShell cmdlet can be used to obtain account "
            "names given a role or permissions group in Office 365.(Citation: Microsoft msolrolemember)(Citation: GitHub Raindance) "
            "The Azure CLI (AZ CLI) also provides an interface to obtain user accounts with authenticated access to a domain. "
            "The command <code>az ad user list</code> will list all users within a domain.(Citation: Microsoft AZ CLI)(Citation: Black Hills Red Teaming MS AD Azure, 2018) "
            "The AWS command <code>aws iam list-users</code> may be used to obtain a list of users in the current account while "
            "<code>aws iam list-roles</code> can obtain IAM roles that have a specified path prefix.(Citation: AWS List Roles)(Citation: AWS List Users) "
            "In GCP, <code>gcloud iam service-accounts list</code> and <code>gcloud projects get-iam-policy</code> may be used to "
            "obtain a listing of service accounts and users in a project.(Citation: Google Cloud - IAM Servie Accounts List API)"
        ),
        "tags": [
            "enterprise-attack",
            "Discovery",
            "Cloud",
            "Office 365",
            "Azure AD",
            "AWS IAM",
            "GCP"
        ],
        "tactic": "Discovery",  # Associated MITRE ATT&CK tactic
        "protocol": "",  # (Not a traditional network protocol; uses various cloud/API calls)
        "os": "Cloud (Azure, AWS, GCP)",  # Targeted operating systems/environments
        "tips": [
            "Monitor processes, command-line arguments, and logs for account enumeration commands (e.g., Get-MsolRoleMember, az ad user list, aws iam list-users, gcloud iam service-accounts list).",
            "Correlate cloud-based account discovery attempts with other suspicious activities (e.g., Lateral Movement or privilege escalation)."
        ],
        "data_sources": (
            "Cloud Service, Command, Windows Powershell, Active Directory, User Account"
        ),
        "log_sources": [
            {
                "type": "Cloud Service",
                "source": "Azure AD / AWS IAM / GCP IAM logs",
                "destination": "Centralized SIEM or Cloud Logging Service"
            }
        ],
        "source_artifacts": [
            {
                "type": "Command",
                "location": "Shell/CLI (e.g., PowerShell, AZ CLI, AWS CLI, GCloud CLI)",
                "identify": "Usage of account enumeration commands"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Log",
                "location": "Cloud Service logs (e.g., Azure Activity Log, CloudTrail, GCP Logs)",
                "identify": "Evidence of account listing requests"
            }
        ],
        "detection_methods": [
            "Monitor usage of known account discovery commands in logs and process metadata.",
            "Alert on unusual or high-frequency enumeration of cloud accounts from unexpected hosts or IP addresses."
        ],
        "apt": [
            "Nobelium"  # Example: known to use cloud-based enumeration (per MSTIC reporting)
        ],
        "spl_query": [
            # Example Splunk query (literal \n| usage if needed in multiline queries)
            "index=cloud_logs source=\"azure_activity\" \"az ad user list\" \n| stats count by user, src_ip",
            "index=cloud_logs source=\"aws_cloudtrail\" eventName=\"ListUsers\" \n| stats count by userIdentity.arn, sourceIPAddress"
        ],
        "hunt_steps": [
            "Review recent cloud CLI usage for unusual commands or parameters.",
            "Identify spikes in 'list users' or 'list roles' commands in AWS, Azure, GCP logs.",
            "Correlate enumerations with subsequent lateral movement or privilege escalation events."
        ],
        "expected_outcomes": [
            "Identify instances of suspicious cloud account enumeration that may precede privilege escalation or lateral movement."
        ],
        "false_positive": (
            "Legitimate administrative scripts or processes that regularly query user lists can trigger these alerts. "
            "Review context (e.g., time, user role, associated IP) to confirm authenticity."
        ),
        "clearing_steps": [
            "Revoke any unauthorized access tokens and credentials.",
            "Review and adjust IAM roles and policies to adhere to the principle of least privilege.",
            "Rotate compromised credentials and audit recent activity."
        ],
        "mitre_mapping": [
            {
                "tactic": "Lateral Movement",
                "technique": "T1078 (Valid Accounts)",
                "example": "Adversaries may use discovered accounts for lateral movement."
            }
        ],
        "watchlist": [
            "Frequent or scripted usage of 'list' commands in cloud CLIs from non-administrative users.",
            "Enumeration activity from new or unexpected IP ranges."
        ],
        "enhancements": [
            "Implement conditional access or MFA for cloud administrative commands.",
            "Correlate cloud discovery events with on-premises AD logs for a holistic view."
        ],
        "summary": (
            "Account Discovery: Cloud Account (T1087.004) involves enumerating cloud-based user or service accounts to "
            "understand the target environment and identify potential paths for further compromise."
        ),
        "remediation": (
            "Use strict access controls, least privilege, and robust logging for cloud identity systems. "
            "Implement MFA and monitor for unusual enumeration patterns."
        ),
        "improvements": (
            "Enhance detection by integrating cloud-native logs (e.g., Azure AD logs, AWS CloudTrail, GCP logs) "
            "with on-premises SIEM solutions. Apply anomaly detection to spot irregular enumeration patterns."
        )
    }
