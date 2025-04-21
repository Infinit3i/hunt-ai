def get_content():
    return {
        "id": "T1578",
        "url_id": "T1578",
        "title": "Modify Cloud Compute Infrastructure",
        "description": "Adversaries may attempt to modify a cloud account's compute infrastructure to evade defenses, maintain access, or remove evidence. These modifications can include creating, deleting, or changing components such as virtual machines, snapshots, and volumes. By manipulating these resources, adversaries can escalate privileges, hide in unused regions, exfiltrate data, or execute code within an environment while avoiding detection.",
        "tags": ["cloud", "evasion", "compute", "snapshot", "virtual machine", "IaaS"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "IaaS",
        "tips": [
            "Monitor infrastructure changes with correlation to identity and role activity.",
            "Track lifecycle events such as creation/deletion of snapshots or volumes.",
            "Tag and log all cloud modifications for traceability."
        ],
        "data_sources": "Cloud Service: Cloud Service Metadata, Instance: Instance Creation, Instance: Instance Deletion, Instance: Instance Metadata, Instance: Instance Modification, Instance: Instance Start, Instance: Instance Stop, Snapshot: Snapshot Creation, Snapshot: Snapshot Deletion, Snapshot: Snapshot Metadata, Snapshot: Snapshot Modification, Volume: Volume Creation, Volume: Volume Deletion, Volume: Volume Metadata, Volume: Volume Modification",
        "log_sources": [
            {"type": "Instance", "source": "Instance Creation", "destination": ""},
            {"type": "Instance", "source": "Instance Deletion", "destination": ""},
            {"type": "Snapshot", "source": "Snapshot Creation", "destination": ""},
            {"type": "Snapshot", "source": "Snapshot Deletion", "destination": ""},
            {"type": "Volume", "source": "Volume Creation", "destination": ""},
            {"type": "Volume", "source": "Volume Deletion", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "CloudTrail or equivalent logs", "location": "Cloud provider", "identify": "resource modification events"},
            {"type": "Audit log snapshots", "location": "Storage bucket or audit service", "identify": "sudden infrastructure changes"}
        ],
        "destination_artifacts": [
            {"type": "New Instances", "location": "Compromised region", "identify": "Unexpected boot sources or mounted volumes"},
            {"type": "Snapshots or Volumes", "location": "Exfil path", "identify": "Misconfigured public access or cross-region mounts"}
        ],
        "detection_methods": [
            "Correlate instance and snapshot operations with user privileges and access patterns",
            "Monitor volume/snapshot activity alongside unusual traffic to external destinations",
            "Trigger alerts for snapshot creation, mount, and deletion in short succession"
        ],
        "apt": ["UNC3944", "APT29", "SCATTERED SPIDER"],
        "spl_query": [
            "index=cloud_logs (eventName=\"CreateSnapshot\" OR eventName=\"TerminateInstances\" OR eventName=\"RunInstances\")\n| stats count by userIdentity.arn, eventName, requestParameters.*, eventTime"
        ],
        "hunt_steps": [
            "List users that performed snapshot or VM changes in the last 14 days",
            "Identify any new or temporary instances created outside normal hours",
            "Check for signs of policy tampering or region abuse"
        ],
        "expected_outcomes": [
            "Uncover stealthy creation or removal of VMs and snapshots",
            "Detect lateral movement via volume/snapshot-based data access",
            "Surface evasion techniques like resource deletion or region switching"
        ],
        "false_positive": "Legitimate DevOps and backup operations may mimic this behavior. Use tagging, naming conventions, or change windows to distinguish authorized modifications.",
        "clearing_steps": [
            "Revert unauthorized infrastructure changes",
            "Restrict IAM permissions tied to compute infrastructure management",
            "Perform post-mortem forensic imaging and validate cloud logs for tampering"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1578", "example": "Creating snapshots, modifying policies, and deleting resources post-incident"}
        ],
        "watchlist": [
            "IAM roles performing instance or snapshot actions across multiple regions",
            "Unexpected snapshot activity by non-admin users",
            "Excessive volume cloning or image creation events"
        ],
        "enhancements": [
            "Implement change detection systems across all compute services",
            "Use policy-based anomaly detection tied to resource creation patterns",
            "Require approval workflows for sensitive cloud modifications"
        ],
        "summary": "Cloud infrastructure modifications give adversaries stealthy ways to access, persist, or erase evidence. Proper visibility, tagging, and behavior baselines are vital to mitigate risk.",
        "remediation": "Use tight IAM controls, regional resource restrictions, and tag enforcement to limit untracked infrastructure changes. Investigate all out-of-schedule compute activity.",
        "improvements": "Expand centralized logging to cover volume and snapshot metadata. Apply resource locks and notify on VM deletions outside maintenance windows.",
        "mitre_version": "16.1"
    }
