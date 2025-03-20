def get_content():
    return {
        "id": "T1610",  # Tactic Technique ID
        "url_id": "1610",  # URL segment for technique reference
        "title": "Deploy Container",  # Name of the attack technique
        "description": "Adversaries may deploy a container into an environment to facilitate execution or evade defenses. They may launch containers configured without network rules or user limitations, or use malicious/vulnerable images to further compromise host systems. In Kubernetes, adversaries may deploy privileged containers or workloads (e.g., ReplicaSets, DaemonSets) to gain elevated access and potentially escape to the host.",  # Simple description
        "tags": [
            "Deploy Container",
            "Containers",
            "Kubernetes",
            "Docker",
            "Execution",
            "Defense Evasion",
            "Privileged Container",
            "Kinsing",
            "TeamTNT",
            "Kubernetes Hardening Guide"
        ],  # Up to 10 tags
        "tactic": "Defense Evasion, Execution",  # Associated MITRE ATT&CK tactics
        "protocol": "Containers API / Kubernetes",  # Protocol used in the attack technique
        "os": "Containers",  # Targeted environment
        "tips": [
            "Monitor for suspicious or unknown container images/pods in the environment",
            "Deploy logging agents on Kubernetes nodes and retrieve logs from sidecar proxies",
            "Monitor Docker daemon logs for API calls that deploy containers",
            "Watch for abnormal container creation and runtime parameters"
        ],
        "data_sources": "Application Log: Application Log Content, Container: Container Creation, Container: Container Start, Pod: Pod Creation, Pod: Pod Modification",
        "log_sources": [
            {
                "type": "Application Log",
                "source": "Cluster Management Services (e.g., Kubernetes Dashboard, Kubeflow)",
                "destination": "SIEM"
            },
            {
                "type": "Container",
                "source": "Docker Daemon Logs",
                "destination": "SIEM"
            },
            {
                "type": "Pod",
                "source": "Kubernetes API Server Logs",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Container Image",
                "location": "Local or remote container registry",
                "identify": "Malicious or vulnerable container images"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Container/POD",
                "location": "Target container runtime or Kubernetes cluster",
                "identify": "Newly deployed container for malicious activities"
            }
        ],
        "detection_methods": [
            "Analyze logs from the Docker daemon or Kubernetes API for unexpected container deployments",
            "Review container images for suspicious or unauthorized tags/origins",
            "Monitor cluster-level events and changes to ReplicaSets or DaemonSets"
        ],
        "apt": [],
        "spl_query": [],
        "hunt_steps": [
            "Check cluster logs for newly created pods or containers with unexpected privileges",
            "Identify unusual container images or references to unknown registries",
            "Correlate container deployment events with abnormal network activity or file access"
        ],
        "expected_outcomes": [
            "Detection of malicious or unauthorized container deployments",
            "Identification of suspicious images or configurations enabling privilege escalation",
            "Prevention of container-based lateral movement or host escape attempts"
        ],
        "false_positive": "Legitimate container deployments for testing or ephemeral workloads may appear suspicious. Validate context, scheduling, and authorized user actions.",
        "clearing_steps": [
            "Stop and remove unauthorized containers",
            "Revoke permissions or tokens used to deploy containers",
            "Audit and restrict container registry access"
        ],
        "mitre_mapping": [
            {
                "tactic": "Execution",
                "technique": "Deploy Container (T1610)",
                "example": "Launching a privileged container or DaemonSet in Kubernetes to run malicious payloads"
            }
        ],
        "watchlist": [
            "New container creation with host-level privileges or no network/user restrictions",
            "Image pulls from untrusted registries or unknown sources",
            "Changes to cluster-level workloads (e.g., DaemonSets, ReplicaSets) without proper authorization"
        ],
        "enhancements": [
            "Enforce least privilege in container orchestration platforms (Kubernetes RBAC)",
            "Use admission controllers (e.g., Gatekeeper, OPA) to block unauthorized container specs",
            "Implement container image scanning to detect malicious or vulnerable images"
        ],
        "summary": "Deploying a container with improper restrictions or malicious images can allow adversaries to evade defenses, achieve execution, and potentially escalate privileges in containerized environments.",
        "remediation": "Restrict access to container deployment APIs, enforce RBAC policies, regularly scan container images, and monitor cluster logs for suspicious container creations.",
        "improvements": "Implement strong identity and access management for container orchestration, use network policies to restrict container traffic, and apply runtime security tools to detect suspicious container behaviors."
    }
