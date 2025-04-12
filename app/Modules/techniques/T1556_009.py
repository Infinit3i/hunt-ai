def get_content():
    return {
        "id": "T1556.009",
        "url_id": "T1556/009",
        "title": "Modify Authentication Process: Conditional Access Policies",
        "description": "Adversaries may disable or modify conditional access policies to enable persistent access to compromised accounts. Conditional access policies are additional verifications used by identity providers and identity and access management systems to determine whether a user should be granted access to a resource. For example, in Entra ID, Okta, and JumpCloud, users can be denied access to applications based on their IP address, device enrollment status, and use of multi-factor authentication. In some cases, identity providers may also support the use of risk-based metrics to deny sign-ins based on a variety of indicators. In AWS and GCP, IAM policies can contain `condition` attributes that verify arbitrary constraints such as the source IP, the date the request was made, and the nature of the resources or regions being requested. These measures help to prevent compromised credentials from resulting in unauthorized access to data or resources, as well as limit user permissions to only those required. By modifying conditional access policies, such as adding additional trusted IP ranges, removing Multi-Factor Authentication requirements, or allowing additional Unused/Unsupported Cloud Regions, adversaries may be able to ensure persistent access to accounts and circumvent defensive measures.",
        "tags": ["Credential Access", "Defense Evasion", "Persistence", "Conditional Access", "Cloud"],
        "tactic": "Credential Access",
        "protocol": "",
        "os": "IaaS, Identity Provider",
        "tips": [
            "Audit conditional access policy changes regularly.",
            "Log all administrative actions in identity provider dashboards.",
            "Monitor changes to multi-factor and IP restriction rules.",
            "Validate policy exclusions against known administrators only."
        ],
        "data_sources": "Active Directory: Active Directory Object Modification, Cloud Service: Cloud Service Modification",
        "log_sources": [
            {"type": "Active Directory", "source": "", "destination": ""},
            {"type": "Cloud Service", "source": "", "destination": ""}
        ],
        "source_artifacts": [],
        "destination_artifacts": [],
        "detection_methods": [
            "Detect changes to conditional access policy definitions",
            "Audit IP-based access rule modifications",
            "Monitor administrative logins performing access policy updates"
        ],
        "apt": [],
        "spl_query": [
            "index=cloud sourcetype=azure:monitor category=Policy action=modified policy_name=ConditionalAccess | stats count by user, policy_name, modified_properties",
            "index=cloud sourcetype=aws:iam eventName=PutRolePolicy OR eventName=PutUserPolicy | search condition | stats count by userName, requestParameters"
        ],
        "hunt_steps": [
            "Query recent modifications to conditional access rules across identity providers",
            "Check for excessive IP address range inclusions or removal of MFA requirements",
            "Review role permissions for policy editing capabilities",
            "Identify any dormant policies that may have been reactivated"
        ],
        "expected_outcomes": [
            "Uncover unauthorized alterations to authentication constraints",
            "Restore legitimate conditional access boundaries to prevent unauthorized persistence"
        ],
        "false_positive": "Legitimate admin activity or policy changes under new compliance requirements. Confirm changes with policy owners.",
        "clearing_steps": [
            "Revert altered conditional access configurations",
            "Reinstate removed MFA and risk-based checks",
            "Notify security teams of suspicious changes and re-evaluate admin privileges"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview",
            "https://attack.mitre.org/techniques/T1556/009"
        ],
        "mitre_mapping": [
            {"tactic": "Credential Access", "technique": "T1556.009", "example": "Adversary modifies identity platform access policy to remove MFA and widen trusted IP ranges."}
        ],
        "watchlist": [
            "Conditional access policy changes involving IP or MFA",
            "High-risk sign-ins lacking expected access control verification",
            "New exclusions added to baseline access policies"
        ],
        "enhancements": [
            "Set up conditional access policy change alerting",
            "Deploy immutable policy backup validation mechanisms"
        ],
        "summary": "This technique abuses identity access configuration flexibility to modify or remove verification mechanisms, allowing unauthorized persistence through weakened conditional access controls.",
        "remediation": "Restrict policy editing permissions, audit identity platform rulesets, and enforce MFA across sensitive user groups.",
        "improvements": "Enable conditional access policy change logs and integrate policy comparison analytics into SIEM tools.",
        "mitre_version": "16.1"
    }
