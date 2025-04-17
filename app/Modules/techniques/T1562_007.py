def get_content():
    return {
        "id": "T1562.007",
        "url_id": "T1562/007",
        "title": "Impair Defenses: Disable or Modify Cloud Firewall",
        "description": "Adversaries may disable or modify a firewall within a cloud environment to bypass controls that limit access to cloud resources. Cloud firewalls are separate from system firewalls that are described in [Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004).\n\nCloud environments typically utilize restrictive security groups and firewall rules that only allow network activity from trusted IP addresses via expected ports and protocols. An adversary with appropriate permissions may introduce new firewall rules or policies to allow access into a victim cloud environment and/or move laterally from the cloud control plane to the data plane.\n\nFor example, an adversary may use a script or utility that creates new ingress rules in existing security groups (or creates new security groups entirely) to allow any TCP/IP connectivity to a cloud-hosted instance. They may also remove networking limitations to support traffic associated with malicious activity (such as cryptomining).\n\nModifying or disabling a cloud firewall may enable adversary C2 communications, lateral movement, and/or data exfiltration that would otherwise not be allowed. It may also be used to open up resources for Brute Force or Endpoint Denial of Service.",
        "tags": ["cloud", "firewall", "evasion", "security group", "IaaS", "lateral movement", "AWS", "Azure"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "IaaS",
        "tips": [
            "Enable logging for security group and firewall rule changes in your cloud platform.",
            "Review newly created or modified rules against least privilege policies.",
            "Use automation tools to revert unauthorized rule changes."
        ],
        "data_sources": "Firewall",
        "log_sources": [
            {"type": "Firewall", "source": "Cloud Control Plane", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Firewall Rule Modification", "location": "AWS Security Group, Azure NSG", "identify": "New rules permitting all traffic"},
            {"type": "IAM Action", "location": "CloudTrail, Azure Activity Logs", "identify": "CreateSecurityGroup, AuthorizeSecurityGroupIngress"}
        ],
        "destination_artifacts": [
            {"type": "Cloud Firewall State", "location": "Security group configurations", "identify": "Unrestricted ingress or egress"}
        ],
        "detection_methods": [
            "Audit logs for security group/firewall creation or modification actions",
            "Alert on security groups allowing 0.0.0.0/0 or overly broad CIDR ranges",
            "Correlate changes with user identity and time of access"
        ],
        "apt": ["UNC3886"],
        "spl_query": [
            "index=cloudtrail eventName IN (AuthorizeSecurityGroupIngress, RevokeSecurityGroupEgress, CreateSecurityGroup) \n| stats count by userIdentity.arn, eventName, sourceIPAddress"
        ],
        "hunt_steps": [
            "List security groups with overly permissive rules (e.g., 0.0.0.0/0 on sensitive ports)",
            "Identify IAM roles that made changes to security groups",
            "Review just-in-time modifications followed by high volume access"
        ],
        "expected_outcomes": [
            "Detection of misconfigured or maliciously altered cloud firewall rules",
            "Correlation of suspicious ingress/egress activity with firewall modifications"
        ],
        "false_positive": "Administrators or CI/CD pipelines may update firewall rules for temporary deployments. Validate intent before escalating.",
        "clearing_steps": [
            "Revert to previous known-good firewall rule sets",
            "Restrict IAM permissions to modify firewall rules",
            "Enforce compliance with security policies using infrastructure-as-code tools"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1562.007", "example": "Creating permissive security group rules in AWS to allow inbound SSH access from any IP"}
        ],
        "watchlist": [
            "Creation of new security groups with allow-all rules",
            "Use of high-privilege IAM roles outside approved windows",
            "Ingress rule changes on production-facing instances"
        ],
        "enhancements": [
            "Implement service control policies to prevent direct modification of firewall rules",
            "Use runtime protection to enforce expected network configurations",
            "Monitor IaC drift with Terraform or CloudFormation detection tools"
        ],
        "summary": "T1562.007 describes adversarial techniques to disable or modify cloud-based firewalls or security groups. These changes often aim to open access for C2, lateral movement, or brute force attacks, and should be carefully logged and audited in cloud environments.",
        "remediation": "Use policy enforcement to restrict who can modify cloud firewall rules. Continuously monitor and alert on policy violations.",
        "improvements": "Deploy continuous compliance checks and anomaly detection models on firewall configuration changes.",
        "mitre_version": "16.1"
    }
