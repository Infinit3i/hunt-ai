def get_content():
    return {
        "id": "T1613",  # Tactic Technique ID
        "url_id": "1613",  # URL segment for technique reference
        "title": "Container and Resource Discovery",  # Name of the attack technique
        "description": (
            "Adversaries may attempt to discover containers and other resources within a containerized "
            "environment (e.g., images, deployments, pods, nodes, cluster status). By using the Docker or "
            "Kubernetes APIs, adversaries can gather information about running containers, configuration, "
            "and potentially the underlying infrastructure or cloud provider. Such discovery can inform "
            "later actions, including lateral movement or execution methods."
        ),
        "tags": [
            "containers",
            "docker",
            "kubernetes",
            "discovery",
            "resource discovery"
        ],
        "tactic": "Discovery",  # Associated MITRE ATT&CK tactic
        "protocol": "Various (Docker API, Kubernetes API)",  # Protocol used in the attack technique
        "os": "Containers",  # Targeted environment
        "tips": [
            "Establish centralized logging for container and Kubernetes components.",
            "Deploy logging agents on Kubernetes nodes or sidecar proxies to capture relevant events.",
            "Restrict and monitor API calls related to container enumeration, especially from unexpected users or service accounts."
        ],
        "data_sources": "Container: Container Enumeration, Pod: Pod Enumeration",  # Data sources relevant to detection
        "log_sources": [
            {"type": "Container", "source": "Container Enumeration", "destination": ""},
            {"type": "Pod", "source": "Pod Enumeration", "destination": ""}
        ],
        "source_artifacts": [
            {
                "type": "Container Logs",
                "location": "Container host or orchestration platform",
                "identify": "Identify commands or API calls enumerating container resources"
            }
        ],
        "destination_artifacts": [
            {
                "type": "API Requests",
                "location": "Docker/Kubernetes APIs",
                "identify": "Look for suspicious or unauthorized resource discovery calls"
            }
        ],
        "detection_methods": [
            "Monitor container and Kubernetes logs for unexpected discovery actions (e.g., listing pods, deployments, nodes).",
            "Track user or service account actions in Kubernetes dashboards and web applications.",
            "Correlate changes in resource enumeration with known threat actor TTPs or unusual lateral movement attempts."
        ],
        "apt": [],  # No specific APT groups mentioned
        "spl_query": [
            "index=container_logs OR index=kubernetes \n| stats count by user, api_call, resource_type"
        ],
        "hunt_steps": [
            "Review Kubernetes API server logs for unusual or unauthorized requests to list pods, deployments, or nodes.",
            "Check Docker daemon logs for suspicious container enumeration commands (e.g., 'docker ps', 'docker inspect').",
            "Identify any newly created service accounts or roles with high privileges related to cluster visibility."
        ],
        "expected_outcomes": [
            "Detection of unauthorized container or cluster resource discovery actions.",
            "Identification of suspicious API calls that may precede lateral movement or privilege escalation."
        ],
        "false_positive": (
            "Legitimate administrative or operational tasks may involve frequent enumeration of containers and pods. "
            "Validate these activities against known workflows, users, and change management records."
        ),
        "clearing_steps": [
            "Revoke or restrict excessive permissions for accounts identified as performing unauthorized discovery.",
            "Review and rotate credentials/tokens associated with compromised accounts or service accounts.",
            "Harden container orchestrator configurations (e.g., enforcing RBAC and network policies)."
        ],
        "mitre_mapping": [
            {
                "tactic": "Discovery",
                "technique": "Container Enumeration (T1613)",
                "example": "Adversaries enumerating containers, pods, and deployments via Docker or Kubernetes APIs."
            }
        ],
        "watchlist": [
            "Accounts performing atypical resource discovery commands (docker ps, kubectl get pods, etc.).",
            "Repeated listing of container resources in a short timeframe from unknown IP addresses.",
            "Unusual activity within the Kubernetes dashboard or other cluster management interfaces."
        ],
        "enhancements": [
            "Enable role-based access control (RBAC) with least privilege for container administration.",
            "Implement admission controllers to restrict unauthorized access or excessive permissions.",
            "Use container security solutions that log and alert on suspicious enumeration activities."
        ],
        "summary": (
            "Container and resource discovery provides adversaries with insights into the containerized environment, "
            "including active containers, configurations, and orchestrator details. This information can be "
            "leveraged for subsequent lateral movement, privilege escalation, or execution methods."
        ),
        "remediation": (
            "Limit access to container and Kubernetes APIs, enforce strict authentication and authorization, "
            "and regularly audit permissions and logs to detect and respond to unauthorized discovery attempts."
        ),
        "improvements": (
            "Adopt continuous monitoring of container and cluster APIs, integrate with SIEM solutions for "
            "automated correlation, and periodically review role definitions and service accounts to "
            "minimize overprivileged configurations."
        )
    }
