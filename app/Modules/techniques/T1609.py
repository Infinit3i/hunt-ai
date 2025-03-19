def get_content():
    return {
        "id": "T1609",  # Tactic Technique ID
        "url_id": "1609",  # URL segment for technique reference
        "title": "Container Administration Command",  # Name of the attack technique
        "description": (
            "Adversaries may abuse a container administration service (e.g., Docker daemon, Kubernetes API server, or kubelet) "
            "to execute commands within a container. This can involve specifying an entrypoint to run a script/command in a newly "
            "deployed container or using commands such as 'docker exec' or 'kubectl exec' to gain remote execution. If an adversary "
            "has sufficient permissions, these services can provide full access to the container environment."
        ),
        "tags": [
            "containers",
            "docker",
            "kubernetes",
            "execution",
            "command execution"
        ],
        "tactic": "Execution",  # Associated MITRE ATT&CK tactic
        "protocol": "Various (Docker CLI, Kubernetes API, kubelet, etc.)",  # Protocol used in the attack technique
        "os": "Containers",  # Targeted environment
        "tips": [
            "Enable and monitor container administration service logs (Docker daemon logs, Kubernetes API server logs, kubelet logs).",
            "Implement least-privilege access controls (RBAC) to limit who can execute commands in containers.",
            "Use container-level security contexts (e.g., seccomp, AppArmor, SELinux) to restrict actions inside containers."
        ],
        "data_sources": "Command: Command Execution, Process: Process Creation",  # Data sources relevant to detection
        "log_sources": [
            {"type": "Command", "source": "Command Execution", "destination": ""},
            {"type": "Process", "source": "Process Creation", "destination": ""}
        ],
        "source_artifacts": [
            {
                "type": "Container Logs",
                "location": "Container host or orchestration platform",
                "identify": "Identify commands run inside the container"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Process Execution",
                "location": "Container or host process table",
                "identify": "Unusual or unauthorized commands"
            }
        ],
        "detection_methods": [
            "Capture and analyze process execution with command-line arguments on the container and underlying host.",
            "Review Docker daemon logs or Kubernetes system component logs for unexpected exec or container creation events.",
            "Monitor for privileged container launches or suspicious container runtime configurations (e.g., mounting the Docker socket)."
        ],
        "apt": [],  # No specific APT groups listed in the technique
        "spl_query": [
            "index=container \n| stats count by container_id, command, user"
        ],
        "hunt_steps": [
            "Identify and investigate containers that run with elevated privileges or unusual entrypoints.",
            "Correlate Docker/Kubernetes events with process creation logs to detect malicious command execution.",
            "Search for known malicious scripts or binaries inside containers and container images."
        ],
        "expected_outcomes": [
            "Detection of unauthorized commands executed within container environments.",
            "Identification of adversary abuse of container administration services for lateral movement or privilege escalation."
        ],
        "false_positive": (
            "Legitimate container management operations (e.g., maintenance scripts, admin troubleshooting) may appear suspicious. "
            "Validate through change management records and admin approvals."
        ),
        "clearing_steps": [
            "Stop or remove malicious containers, ensuring no residual files remain.",
            "Rotate credentials and tokens associated with container administration services.",
            "Apply patches or configuration changes to container orchestrators to reduce future exploitation risk."
        ],
        "mitre_mapping": [
            {
                "tactic": "Execution",
                "technique": "Exploitation for Container Administration (T1610 is related but not official); or Lateral Movement in container environments",
                "example": "After gaining access to Docker or Kubernetes, an adversary may pivot to other containers or hosts."
            }
        ],
        "watchlist": [
            "Unusual container creation commands or entrypoints.",
            "Repeated or suspicious 'docker exec' or 'kubectl exec' usage.",
            "Containers launched with privileged flags or host file system mounts."
        ],
        "enhancements": [
            "Implement Kubernetes admission controllers to enforce security policies on new containers.",
            "Enable Docker daemon socket protection and restrict direct access to it.",
            "Use container security solutions (e.g., runtime threat detection, image scanning) to monitor container behavior."
        ],
        "summary": (
            "Container administration commands enable adversaries to execute arbitrary code inside containerized "
            "environments. By leveraging Docker, Kubernetes, or similar services, attackers can escalate privileges, "
            "move laterally, or launch additional malicious operations."
        ),
        "remediation": (
            "Enforce strict RBAC in container orchestrators, restrict direct access to the Docker daemon, implement strong authentication "
            "and authorization, and regularly audit container runtime configurations."
        ),
        "improvements": (
            "Integrate container logs and orchestration events into a SIEM, implement automated policy enforcement (admission controllers), "
            "and adopt continuous scanning of container images for vulnerabilities and malicious content."
        )
    }
