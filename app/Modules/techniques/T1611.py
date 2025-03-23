def get_content():
    return {
        "id": "T1611",
        "url_id": "T1611",
        "title": "Escape to Host",
        "description": "Adversaries may break out of a container to gain access to the underlying host. This can allow access to other containerized resources or the host itself.",
        "tags": ["container breakout", "privilege escalation", "docker", "kubernetes", "escape"],
        "tactic": "Privilege Escalation",
        "protocol": "",
        "os": "Containers, Linux, Windows",
        "tips": [
            "Restrict use of privileged containers and avoid hostPath volume mounts.",
            "Audit usage of syscalls like `unshare`, `mount`, and `keyctl`.",
            "Apply kernel hardening and container escape prevention policies."
        ],
        "data_sources": "Container: Container Creation, Kernel: Kernel Module Load, Process: OS API Execution, Process: Process Creation, Volume: Volume Modification",
        "log_sources": [
            {"type": "Container", "source": "Orchestration Logs", "destination": "Monitoring Stack"},
            {"type": "Process", "source": "Container OS", "destination": "Host SIEM"},
            {"type": "Kernel", "source": "Host OS", "destination": "Security Tooling"}
        ],
        "source_artifacts": [
            {"type": "Malicious Image", "location": "/var/lib/docker/", "identify": "Suspicious image with host mount or privileged flag"}
        ],
        "destination_artifacts": [
            {"type": "Host Persistence", "location": "/etc/cron.d/", "identify": "Container escape writing cronjob on host"}
        ],
        "detection_methods": [
            "Monitor syscalls and seccomp violations from containers",
            "Track new privileged container launches or abnormal volume mounts",
            "Alert on Docker socket (`docker.sock`) access inside containers"
        ],
        "apt": [],
        "spl_query": [
            "index=container_logs event.action=create volume.hostPath=*\n| stats count by container_id, image, user"
        ],
        "hunt_steps": [
            "Identify containers running as root with host mount paths",
            "Check if `/var/run/docker.sock` is exposed inside containers",
            "Look for syscalls indicating `unshare`, `keyctl`, or `mount` usage from containers"
        ],
        "expected_outcomes": [
            "Discovery of container configuration allowing breakout",
            "Detection of post-breakout artifacts like host modifications"
        ],
        "false_positive": "Administrators may intentionally run privileged containers for debugging or maintenance. Validate user and context.",
        "clearing_steps": [
            "Stop and remove the container with breakout behavior",
            "Revoke any credentials used from the host",
            "Reimage the host if root compromise occurred"
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1068", "example": "Exploitation for Privilege Escalation"},
            {"tactic": "Persistence", "technique": "T1543.003", "example": "Create or Modify System Process: Windows Service"}
        ],
        "watchlist": [
            "Access to `/var/run/docker.sock`",
            "Container processes attempting `sys_module` or `mount` capabilities"
        ],
        "enhancements": [
            "Use AppArmor or SELinux profiles for containers",
            "Enforce `readOnlyRootFilesystem: true` in Kubernetes security contexts"
        ],
        "summary": "This technique allows adversaries to escape the container boundary and gain host access, potentially affecting all co-located workloads.",
        "remediation": "Enforce least privilege, disable privileged mode, and apply runtime security tools like Falco or AppArmor.",
        "improvements": "Implement pod security policies, runtime behavior monitoring, and container scanning for escape paths.",
        "mitre_version": "16.1"
    }
