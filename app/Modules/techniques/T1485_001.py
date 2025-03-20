def get_content():
    return {
        "id": "T1485.001",  # Tactic Technique ID
        "url_id": "1485/001",  # URL segment for technique reference
        "title": "Data Destruction: Lifecycle-Triggered Deletion",  # Name of the attack technique
        "description": "Adversaries may modify the lifecycle policies of a cloud storage bucket to destroy all objects stored within. Cloud storage buckets often allow users to set policies to automate migration, archival, or deletion of objects. With sufficient permissions, an adversary can delete all objects at once using API calls such as PutBucketLifecycle.",  # Simple description of the attack technique
        "tags": ["Data Destruction", "Cloud Storage", "Lifecycle", "Deletion"],
        "tactic": "Impact",  # Associated MITRE ATT&CK tactic
        "protocol": "Cloud Storage API",  # Protocol used in the attack technique
        "os": "IaaS/Cloud",  # Targeted operating systems (or environments)
        "tips": [
            "Monitor changes to lifecycle policies on cloud storage buckets",
            "Restrict permissions for modifying lifecycle configurations",
            "Audit API calls such as PutBucketLifecycle for unauthorized activity"
        ],
        "data_sources": "Cloud Storage: Cloud Storage Modification",  # Data sources
        "log_sources": [  # Logs necessary for detection
            {"type": "Cloud Storage", "source": "Cloud Storage Logs", "destination": "Cloud Storage Logs"}
        ],
        "source_artifacts": [  # Artifacts generated on the source machine
            {"type": "Lifecycle Policy", "location": "Cloud Storage Bucket", "identify": "Policy modification logs"}
        ],
        "destination_artifacts": [  # Artifacts generated on the destination machine
            {"type": "Deleted Objects", "location": "Cloud Storage Bucket", "identify": "Absence of expected objects"}
        ],
        "detection_methods": [
            "Monitor for PutBucketLifecycle API calls",
            "Audit lifecycle policy changes in cloud environments",
            "Correlate unexpected object deletions with policy modifications"
        ],
        "apt": [],  # APT groups known to use this technique
        "spl_query": [
            "index=cloudtrail sourcetype=aws:cloudtrail eventName=PutBucketLifecycle\n| stats count by userName"
        ],
        "hunt_steps": [
            "Review recent modifications to cloud storage lifecycle policies",
            "Verify if permissions for modifying lifecycle configurations are appropriate",
            "Correlate API activity with unexpected mass deletion events"
        ],
        "expected_outcomes": [
            "Rapid deletion of objects in cloud storage buckets",
            "Detection of anomalous API calls in cloud logs",
            "Identification of unauthorized lifecycle policy changes"
        ],
        "false_positive": "Legitimate administrative updates to lifecycle policies during scheduled maintenance may trigger alerts. Validate changes against maintenance records.",
        "clearing_steps": [
            "Revert unauthorized lifecycle policy modifications",
            "Restore deleted objects from backup",
            "Audit and tighten permissions on lifecycle configurations"
        ],
        "mitre_mapping": [
            {"tactic": "Impact", "technique": "Financial Theft", "example": "Data destruction may support ransom extortion schemes"},
            {"tactic": "Defense Evasion", "technique": "Indicator Removal", "example": "Modifying lifecycle policies to remove cloud logs"}
        ],
        "watchlist": [
            "Unusual modifications to lifecycle policies",
            "Spikes in PutBucketLifecycle API calls",
            "Mass deletion events in cloud storage environments"
        ],
        "enhancements": [
            "Integrate lifecycle change alerts into SIEM systems",
            "Implement strict permission controls on cloud storage management",
            "Conduct regular audits of cloud storage configurations"
        ],
        "summary": "This technique involves modifying cloud storage lifecycle policies to trigger mass deletion of stored objects, potentially disrupting operations and impacting data availability.",
        "remediation": "Enforce least privilege for lifecycle modifications, monitor API activity closely, and maintain regular backups to mitigate data loss.",
        "improvements": "Enhance logging and alerting around lifecycle policy changes and regularly review permissions to ensure proper cloud storage management."
    }
