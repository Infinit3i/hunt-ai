def get_content():
    return {
        "id": "T1098.006",
        "url_id": "1098/006",
        "title": "Account Manipulation: Additional Container Cluster Roles",
        "description": (
            "Adversaries may add roles or permissions to container cluster accounts (e.g., Kubernetes RoleBindings) "
            "to maintain persistent or escalated privileges within container orchestration environments."
        ),
        "tags": [
            "enterprise-attack",
            "Persistence",
            "Privilege Escalation",
            "Containers"
        ],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "Containers",
        "tips": [
            "Monitor for new or modified Kubernetes RoleBindings, ClusterRoleBindings, or ABAC policies.",
            "Check for unexpected role assignments to service accounts in container orchestration systems."
        ],
        "data_sources": "Container orchestration logs (Kubernetes API Server logs, etc.)",
        "log_sources": [
            {
                "type": "Containers",
                "source": "Kubernetes API Audit Logs (or equivalent in other orchestrators)",
                "destination": "SIEM or centralized logging"
            }
        ],
        "source_artifacts": [
            {
                "type": "API/CLI Command",
                "location": "Kubernetes or container orchestration CLI/API",
                "identify": "Evidence of role/permission creation or modification"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Log",
                "location": "Kubernetes API Audit Logs",
                "identify": "Creation or modification of roles, role bindings, or ABAC policies"
            }
        ],
        "detection_methods": [
            "Monitor for unexpected creation or modification of RoleBindings, ClusterRoleBindings, or ABAC policies.",
            "Alert on unusual account or service account role assignments."
        ],
        "apt": [],
        "spl_query": [
            # Example Splunk query
            "index=kubernetes_audit (verb=create OR verb=update) (resource=rolebindings OR resource=clusterrolebindings) \n| stats count by user.username, userAgent"
        ],
        "hunt_steps": [
            "Identify newly created or modified roles that grant privileged permissions to unexpected accounts.",
            "Correlate with other suspicious container activity or network anomalies."
        ],
        "expected_outcomes": [
            "Detection of unauthorized or anomalous role/permission modifications in container orchestration environments."
        ],
        "false_positive": (
            "Legitimate cluster administration tasks such as adding roles for new services or teams. "
            "Validate context and timing of changes."
        ),
        "clearing_steps": [
            "Remove or revert unauthorized roles, role bindings, or ABAC policies.",
            "Revoke compromised credentials or tokens used to make these changes."
        ],
        "mitre_mapping": [
            {
                "tactic": "Privilege Escalation",
                "technique": "T1078 (Valid Accounts)",
                "example": "Adversaries may modify permissions of existing container accounts to gain elevated privileges."
            }
        ],
        "watchlist": [
            "Repeated or scripted additions of roles to service accounts in container clusters.",
            "Changes to cluster-wide roles (ClusterRoleBindings) by non-administrative accounts."
        ],
        "enhancements": [
            "Implement role-based access control (RBAC) with least privilege for container orchestration.",
            "Enable detailed audit logging on Kubernetes or other container platforms."
        ],
        "summary": (
            "By adding roles or permissions to container cluster accounts, adversaries can maintain persistent or "
            "escalated access to the orchestration environment."
        ),
        "remediation": (
            "Enforce strict RBAC, review cluster roles regularly, and monitor for abnormal role modifications. "
            "Enable multi-factor authentication and key rotation for cluster admin accounts."
        ),
        "improvements": (
            "Integrate container orchestration audit logs into a SIEM for correlation. "
            "Leverage anomaly detection to identify unusual role assignment patterns."
        )
    }
