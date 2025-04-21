def get_content():
    return {
        "id": "T1666",
        "url_id": "T1666",
        "title": "Modify Cloud Resource Hierarchy",
        "description": "Adversaries may attempt to modify hierarchical structures in infrastructure-as-a-service (IaaS) environments in order to evade defenses and bypass policies. Cloud environments use hierarchical groupings to organize and manage resources at scale. These structures—such as AWS Organizations or Azure Management Groups—allow enforcement of guardrails like Service Control Policies (SCPs) or RBAC at different levels. Adversaries who gain access to privileged accounts may restructure or break out of these hierarchies to avoid logging, bypass controls, or execute stealthy operations. Examples include severing an account from an AWS Organization using the `LeaveOrganization` API, creating new unmonitored accounts, or hijacking Azure subscriptions to operate under different tenants.",
        "tags": ["cloud", "aws", "azure", "defense evasion", "resource hierarchy", "subscription hijacking"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "IaaS",
        "tips": [
            "Track usage of APIs such as `CreateAccount`, `LeaveOrganization`, or Azure subscription management commands",
            "Investigate sudden removal of SCPs or newly created accounts/subscriptions",
            "Audit subscription transfer activity and account movement across tenants"
        ],
        "data_sources": "Cloud Service: Cloud Service Modification",
        "log_sources": [
            {"type": "CloudTrail", "source": "AWS Organizations", "destination": ""},
            {"type": "Azure Activity Logs", "source": "Azure Management Groups", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "API Call", "location": "IAM logs or audit trails", "identify": "LeaveOrganization, CreateAccount"},
            {"type": "Subscription Events", "location": "Azure subscription transfer logs", "identify": "Transfer events or new creation outside admin workflow"}
        ],
        "destination_artifacts": [
            {"type": "Modified Hierarchy", "location": "Cloud Console or audit logs", "identify": "Missing SCPs, unexpected new accounts"},
            {"type": "Tenant Link", "location": "Azure AD or IAM", "identify": "Hijacked or transferred subscriptions"}
        ],
        "detection_methods": [
            "Detect AWS LeaveOrganization, CreateAccount, InviteAccountToOrganization API usage",
            "Monitor Azure subscription creation, transfer, or management group restructuring",
            "Correlate cloud resource changes with IAM activity and geolocation anomalies"
        ],
        "apt": [],
        "spl_query": [
            "index=aws_cloudtrail eventName IN (\"LeaveOrganization\", \"CreateAccount\") \n| stats count by eventName, userIdentity.arn, sourceIPAddress",
            "index=azure_logs operationName IN (\"Create Subscription\", \"Transfer Subscription\") \n| stats count by operationName, identity, resultType"
        ],
        "hunt_steps": [
            "Identify cloud accounts or subscriptions recently removed from parent organizations",
            "Review access policies or SCPs removed from formerly restricted accounts",
            "Audit cloud console for accounts with unexpected naming, billing, or region configurations"
        ],
        "expected_outcomes": [
            "Detection of account separation from org structure",
            "Evidence of unauthorized cloud subscription creation",
            "Changes to cloud billing or policy inheritance patterns"
        ],
        "false_positive": "Cloud engineers may create new accounts or restructure management groups for testing or organizational changes. Verify with change control or DevOps records.",
        "clearing_steps": [
            "Rejoin affected accounts to AWS Organization or Azure Management Group",
            "Reapply missing policies or RBAC to the account/subscription",
            "Revoke unauthorized subscription transfers or initiate incident response"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562.001", "example": "Bypassing SCPs or RBAC through organizational changes"},
            {"tactic": "Persistence", "technique": "T1136.003", "example": "Creating new AWS or Azure accounts/subscriptions for long-term access"}
        ],
        "watchlist": [
            "Cloud accounts leaving org structure",
            "Unexpected subscription creation",
            "API calls indicating resource group manipulation"
        ],
        "enhancements": [
            "Apply SCPs with deny rules for account/organization removal",
            "Enable GuardDuty or Azure Defender for tenant-level policy monitoring",
            "Implement automated alerts for creation of new accounts or resource groups"
        ],
        "summary": "Cloud resource hierarchies offer policy enforcement points. Adversaries may exploit this structure by manipulating how resources are grouped—escaping inherited restrictions or concealing activity in newly created/unmonitored accounts. Monitoring API calls and subscription movement is key to detecting this tactic.",
        "remediation": "Immediately rejoin affected resources to their appropriate management structures and enforce relevant policies. Use conditional access controls and strict privilege separation for high-level IAM roles.",
        "improvements": "Continuously audit organization structure. Enforce MFA and just-in-time access for root or global administrator roles. Automate guardrail reapplication for any detached resources.",
        "mitre_version": "16.1"
    }
