def get_content():
    return {
        "id": "T1580",  # Tactic Technique ID
        "url_id": "1580",  # URL segment for technique reference
        "title": "Cloud Infrastructure Discovery",  # Name of the attack technique
        "description": "An adversary may attempt to discover infrastructure and resources that are available within an infrastructure-as-a-service (IaaS) environment. This includes compute service resources such as instances, virtual machines, and snapshots as well as resources of other services including the storage and database services. Cloud providers offer methods such as APIs and commands issued through CLIs to serve information about infrastructure. An adversary may enumerate resources using a compromised user's access keys to determine which are available to that user. The discovery of these available resources may help adversaries determine their next steps in the Cloud environment, such as establishing Persistence.",
        "tags": [
            "t1580",
            "cloud infrastructure discovery",
            "iaas enumeration",
            "cloud resource discovery",
            "aws describeinstances",
            "azure vm list",
            "gcp compute instances list",
            "cloud security",
            "cloud api enumeration",
            "cloud reconnaissance",
            "cloud storage enumeration",
            "instance enumeration",
            "snapshot enumeration"
        ],
        "tactic": "Discovery",
        "protocol": "IaaS",
        "os": "Cloud Environments",
        "tips": [
            "Monitor cloud API logs for unusual enumeration activity.",
            "Restrict access to cloud discovery APIs with role-based access control.",
            "Use anomaly detection to identify unusual resource discovery patterns.",
            "Implement logging and alerts for excessive API requests from compromised accounts."
        ],
        "data_sources": "Cloud Storage: Cloud Storage Enumeration, Instance: Instance Enumeration, Snapshot: Snapshot Enumeration, Volume: Volume Enumeration",
        "log_sources": [
            {"type": "Cloud Logs", "source": "AWS CloudTrail", "destination": "SIEM"},
            {"type": "Cloud Logs", "source": "Azure Monitor", "destination": "Security Operations"}
        ],
        "source_artifacts": [
            {"type": "API Calls", "location": "Cloud Provider API Logs", "identify": "Discovery API Usage"},
            {"type": "Command History", "location": "/var/log/cloud-discovery.log", "identify": "CLI-based Resource Enumeration"}
        ],
        "destination_artifacts": [
            {"type": "Audit Log", "location": "Cloud Logging System", "identify": "Unauthorized Discovery Attempts"}
        ],
        "detection_methods": ["Cloud API Monitoring", "Behavioral Anomaly Detection for Discovery Requests"],
        "apt": ["Mandiant APT", "Octo Tempest"],
        "spl_query": ["index=cloud_logs | search resource_enumeration"],
        "hunt_steps": ["Detect excessive API calls related to cloud infrastructure discovery.", "Identify suspicious enumeration activity originating from new IPs."],
        "expected_outcomes": ["Detection of unauthorized resource discovery attempts in cloud environments."],
        "false_positive": "Legitimate cloud administration activities may trigger similar API calls.",
        "clearing_steps": ["Audit IAM policies to restrict discovery API access.", "Monitor API request logs for abnormal patterns."],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1580", "example": "An adversary using API calls to enumerate cloud resources and infrastructure."}
        ],
        "watchlist": ["Unexpected cloud API calls", "Unusual discovery activity from new accounts"],
        "enhancements": ["Implement strict IAM policies for discovery API calls.", "Use cloud provider security features to detect unauthorized enumerations."],
        "summary": "Adversaries may use cloud APIs and CLI tools to discover resources in cloud environments, including instances, storage, and databases.",
        "remediation": "Restrict API access to authorized users, monitor API logs, and implement anomaly detection to detect unauthorized discovery attempts.",
        "improvements": "Enhance cloud monitoring by setting up alerts for unusual discovery API usage and excessive enumeration attempts."
    }
