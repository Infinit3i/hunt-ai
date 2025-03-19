def get_content():
    return {
        "id": "T1543.005",
        "url_id": "1543/005",
        "title": "Create or Modify System Process: Container Service",
        "description": "Adversaries may create or modify container or container cluster management tools that run as daemons, agents, or services on individual hosts. This includes software such as Docker, Podman, and Kubernetes components like kubelet. By modifying these services, an adversary may achieve persistence or escalate their privileges on a host.",
        "tags": ["Persistence", "Privilege Escalation", "Containers", "Kubernetes", "Docker"],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "Container Management APIs, Systemd, Kubernetes API",
        "os": ["Containers"],
        "tips": [
            "Monitor for unusual container service modifications.",
            "Detect unauthorized usage of 'docker run' or 'podman run' commands with restart policies.",
            "Review DaemonSet configurations in Kubernetes to ensure they are legitimate."
        ],
        "data_sources": "Container Creation, Command Execution, Service Modification Logs",
        "log_sources": [
            {"type": "Container", "source": "Container Creation", "destination": "System Logs"},
            {"type": "Command", "source": "Command Execution", "destination": "Shell History"}
        ],
        "source_artifacts": [
            {"type": "Container Config", "location": "Docker/Persistence Settings", "identify": "Modified Restart Policies"}
        ],
        "destination_artifacts": [
            {"type": "Kubernetes DaemonSet", "location": "Cluster Configuration", "identify": "Unauthorized Persistent Pods"}
        ],
        "detection_methods": [
            "Monitor for container services configured with 'restart=always'.",
            "Analyze changes in Kubernetes DaemonSets for unauthorized deployments.",
            "Detect privilege escalation attempts using rootful Docker or Podman commands."
        ],
        "apt": ["TeamTNT"],
        "spl_query": [
            "index=containers event_type=container_start | table _time, container_id, image, command, user"
        ],
        "hunt_steps": [
            "Review running containers for unexpected restart policies.",
            "Analyze Kubernetes cluster configurations for unauthorized changes.",
            "Detect malicious container deployments across all nodes."
        ],
        "expected_outcomes": [
            "Detection of unauthorized container persistence mechanisms.",
            "Identification of privilege escalation attempts using container services."
        ],
        "false_positive": "Legitimate container service modifications for maintenance purposes.",
        "clearing_steps": [
            "Disable and remove unauthorized container services.",
            "Audit Kubernetes DaemonSets for unauthorized modifications.",
            "Investigate the origin of container modifications and restart policies."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "Modify Container Services", "example": "An attacker configures a Kubernetes DaemonSet for persistence."}
        ],
        "watchlist": ["Newly created or modified container services with unexpected restart policies."],
        "enhancements": ["Implement stricter monitoring on container service configurations."],
        "summary": "Attackers may create or modify container services to establish persistence. Monitoring container configurations and execution logs can help detect this technique.",
        "remediation": "Review and remove unauthorized container configurations. Strengthen monitoring and logging of container service changes.",
        "improvements": "Enable advanced logging for container execution and service modifications."
    }
