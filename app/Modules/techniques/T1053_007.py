def get_content():
    return {
        "id": "T1053.007",
        "url_id": "T1053/007",
        "title": "Scheduled Task/Job: Container Orchestration Job",
        "description": "Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code.",
        "tags": ["Persistence", "Privilege Escalation", "Execution"],
        "tactic": "Persistence",
        "protocol": "",
        "os": "Containers",
        "tips": [
            "Monitor for the anomalous creation of scheduled jobs in container orchestration environments.",
            "Use logging agents on Kubernetes nodes and retrieve logs from sidecar proxies for application and resource pods."
        ],
        "data_sources": "Container: Container Creation, File: File Creation, Scheduled Job: Scheduled Job Creation",
        "log_sources": [
            {"type": "Container", "source": "Kubernetes CronJob", "destination": ""},
            {"type": "File", "source": "Kubernetes", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Kubernetes CronJob", "location": "/etc/kubernetes/crontab", "identify": "Malicious CronJob entries"}
        ],
        "destination_artifacts": [
            {"type": "Kubernetes CronJob", "location": "/etc/kubernetes/crontab", "identify": "Malicious CronJob entries"}
        ],
        "detection_methods": [
            "Monitor the creation of unusual cron jobs in Kubernetes environments.",
            "Use sidecar proxies to retrieve logs from Kubernetes pods for abnormal activities."
        ],
        "apt": ["Center for Threat-Informed Defense (CTID)", "Vishwas Manral, McAfee", "Yossi Weizman, Azure Defender Research Team"],
        "spl_query": [
            "| index=k8s sourcetype=kubernetes_cron | search *"
        ],
        "hunt_steps": [
            "Monitor Kubernetes cron jobs for unusual scheduling or execution.",
            "Check for abnormal file creation linked to scheduled job deployments."
        ],
        "expected_outcomes": [
            "Identify malicious CronJob deployments in Kubernetes.",
            "Detect unauthorized tasks scheduled in container orchestration systems."
        ],
        "false_positive": "Legitimate CronJob creation for maintenance or updates may trigger false positives.",
        "clearing_steps": [
            "Remove malicious CronJob configurations from Kubernetes.",
            "Restore CronJob files from a known, clean backup."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1053", "example": "Use orchestration tools to schedule container deployment."}
        ],
        "watchlist": [
            "Monitor for suspicious container deployments within Kubernetes environments."
        ],
        "enhancements": [
            "Enhance detection by correlating cron job creation with container activity."
        ],
        "summary": "Adversaries may abuse task scheduling functionality provided by container orchestration tools to deploy malicious containers.",
        "remediation": "Remove malicious CronJob configurations and restore from a clean backup.",
        "improvements": "Implement stronger monitoring for cron job creation in Kubernetes environments.",
        "mitre_version": "16.1"
    }
