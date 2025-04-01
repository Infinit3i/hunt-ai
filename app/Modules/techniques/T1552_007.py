def get_content():
    return {
        "id": "T1552.007",
        "url_id": "T1552/007",
        "title": "Unsecured Credentials: Container API",
        "description": "Adversaries may gather credentials via APIs within a containers environment.",
        "tags": ["credentials", "container", "docker", "kubernetes", "api", "cloud", "infostealer"],
        "tactic": "Credential Access",
        "protocol": "HTTP",
        "os": "Containers",
        "tips": [
            "Harden access to Docker and Kubernetes APIs by enforcing TLS, authentication, and role-based access control (RBAC).",
            "Monitor pod/service account activity for unexpected API interactions.",
            "Audit use of discovery or secrets-related API calls within the cluster."
        ],
        "data_sources": "Command, User Account",
        "log_sources": [
            {"type": "Command", "source": "", "destination": ""},
            {"type": "User Account", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Network Connections", "location": "Docker socket or Kube API", "identify": "Unexpected access to container management APIs"},
            {"type": "Cloud Service", "location": "Container audit logs", "identify": "Access to log scraping or secret discovery endpoints"}
        ],
        "destination_artifacts": [
            {"type": "Logon Session", "location": "Cloud API sessions", "identify": "Use of harvested container credentials for lateral access"}
        ],
        "detection_methods": [
            "Monitor access to the Docker socket (`/var/run/docker.sock`) or Kubernetes API server",
            "Detect abnormal service account activity (accessing secrets, logging endpoints)",
            "Correlate pod/container metadata with requests to discovery or secrets endpoints"
        ],
        "apt": [
            "Peirates"
        ],
        "spl_query": [
            'index=container sourcetype=kube-audit verb="get" objectRef.resource="secrets"\n| stats count by user.username, sourceIPs, userAgent',
            'index=container sourcetype=docker-logs command="*docker logs*"\n| stats count by container_name, host, user'
        ],
        "hunt_steps": [
            "Identify pods or users accessing secrets or token endpoints via the Kubernetes API.",
            "Review Docker logs for commands accessing sensitive logs that may contain credentials.",
            "Look for new service accounts with access to secrets or APIs that were not previously active."
        ],
        "expected_outcomes": [
            "Detection of API access to secret management functions or credential storage",
            "Identification of credential harvesting via logs or mounted volumes"
        ],
        "false_positive": "DevOps pipelines and monitoring tools may access logs or secrets; verify with known service accounts and scheduling patterns.",
        "clearing_steps": [
            "Rotate any secrets accessed during the suspicious activity",
            "Revoke access for compromised service accounts or container roles",
            "Patch and restrict access to container APIs"
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-credential-theft"
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1087.004", "example": "Service account discovery via Kubernetes API"},
            {"tactic": "Collection", "technique": "T1119", "example": "Harvesting credentials through container logs"}
        ],
        "watchlist": [
            "docker.sock", "kubernetes.io/serviceaccount", "api/v1/secrets", "docker logs", "kubectl get secrets"
        ],
        "enhancements": [
            "Enable audit logging for Kubernetes and Docker API interactions",
            "Deploy policy engines like OPA/Gatekeeper to enforce least privilege on container APIs"
        ],
        "summary": "Adversaries can extract credentials by interacting with exposed or misconfigured Docker and Kubernetes APIs.",
        "remediation": "Restrict and authenticate API access, rotate compromised secrets, and monitor for abuse of container management interfaces.",
        "improvements": "Use Kubernetes admission controllers and RBAC to limit access to sensitive endpoints, and enforce secure API access via mutual TLS.",
        "mitre_version": "16.1"
    }
