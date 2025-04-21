def get_content():
    return {
        "id": "T1578.004",
        "url_id": "T1578/004",
        "title": "Modify Cloud Compute Infrastructure: Revert Cloud Instance",
        "description": "Adversaries may revert cloud instances to a previous state via snapshots or use ephemeral storage to remove traces of activity. This can help them evade detection after conducting malicious actions. For example, in virtualized environments such as AWS or GCP, adversaries may restore a snapshot through APIs or the cloud dashboard. Ephemeral storage types, which reset on instance restart, can also be abused to remove forensic evidence.",
        "tags": ["cloud", "evade-detection", "snapshot", "rollback", "ephemeral-storage", "AWS", "GCP"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "IaaS",
        "tips": [
            "Tag approved snapshot operations with metadata to distinguish legitimate rollback actions.",
            "Use immutable logging systems that persist outside of the instance lifecycle.",
            "Monitor for snapshot restores, stop/start events, and sudden configuration resets."
        ],
        "data_sources": "Instance: Instance Metadata, Instance: Instance Modification, Instance: Instance Start, Instance: Instance Stop",
        "log_sources": [
            {"type": "Instance", "source": "Instance Metadata", "destination": ""},
            {"type": "Instance", "source": "Instance Modification", "destination": ""},
            {"type": "Instance", "source": "Instance Start", "destination": ""},
            {"type": "Instance", "source": "Instance Stop", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "API Activity", "location": "Cloud Management Logs", "identify": "Snapshot Restore or Ephemeral Disk Configuration"},
            {"type": "User Action", "location": "Audit Trails", "identify": "Stop/Start or Reboot of VM after malicious task"}
        ],
        "destination_artifacts": [
            {"type": "Snapshot Rollback", "location": "Instance Configuration", "identify": "Restore event with no associated ticket or change record"},
            {"type": "Storage Type Change", "location": "Instance Metadata", "identify": "Switch to ephemeral storage mode"}
        ],
        "detection_methods": [
            "Alert on snapshot restore events not tied to authorized change windows",
            "Monitor usage of ephemeral storage configurations",
            "Detect stop/start cycles for high-value systems"
        ],
        "apt": ["UNC2452", "Chimera", "APT10"],
        "spl_query": [
            "index=cloud_logs eventType IN (\"RestoreSnapshot\", \"StartInstance\", \"StopInstance\")\n| stats count by user, instance, eventType, timestamp"
        ],
        "hunt_steps": [
            "Identify unapproved snapshot restore actions across compute fleet",
            "Correlate stop/start VM operations with known IOC windows",
            "Review audit logs for signs of data deletion before rollback"
        ],
        "expected_outcomes": [
            "Detection of unauthorized restoration of previous VM states",
            "Identification of stop/start operations paired with data clearance",
            "Correlation of ephemeral storage usage with attack timelines"
        ],
        "false_positive": "Legitimate operational rollbacks and storage optimizations may trigger similar events. Use context from ticketing systems and change management logs to validate intent.",
        "clearing_steps": [
            "Reinstate current VM snapshot state after rollback detection",
            "Disable ability to restore from unapproved snapshots",
            "Alert and investigate ephemeral storage reconfiguration"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1578", "example": "Reverting cloud instances to erase attacker activities"}
        ],
        "watchlist": [
            "RestoreSnapshot Events",
            "VM Stop/Start Paired with Low Storage IOCs",
            "Audit Log Gaps Post-Rollback"
        ],
        "enhancements": [
            "Add mandatory tags or headers on approved snapshot rollbacks",
            "Automate snapshot diff checks to flag unauthorized reversion",
            "Integrate with CMDB/change management to validate intent"
        ],
        "summary": "Cloud instance rollback via snapshots or ephemeral storage enables adversaries to erase traces of their activity and evade detection post-compromise.",
        "remediation": "Enforce strict snapshot access controls, monitor rollback activity, use persistent centralized logging, and limit use of ephemeral storage for sensitive workloads.",
        "improvements": "Deploy automated detection for VM state reversion without associated CM/approval processes and flag inconsistent instance lifecycle events.",
        "mitre_version": "16.1"
    }
