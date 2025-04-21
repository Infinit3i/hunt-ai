def get_content():
    return {
        "id": "T1578.003",
        "url_id": "T1578/003",
        "title": "Modify Cloud Compute Infrastructure: Delete Cloud Instance",
        "description": "Adversaries may delete cloud instances (VMs) after malicious activities to remove evidence and evade detection. This tactic eliminates forensic artifacts such as logs and memory. For example, an attacker may create a temporary cloud instance to exfiltrate data or mount a snapshot, then delete the instance to cover tracks. In AWS, this is logged via the `TerminateInstances` event, while Azure and GCP provide similar logs through their activity and audit services.",
        "tags": ["cloud", "evasion", "AWS", "GCP", "Azure", "terminate", "delete-vm"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "IaaS",
        "tips": [
            "Establish a mandatory delay or quarantine period before permanent deletion of instances.",
            "Correlate deletion events with prior unusual behavior like snapshot mounts or external data transfers.",
            "Use write-once storage to store logs and metadata about instance lifecycle events."
        ],
        "data_sources": "Instance: Instance Deletion, Instance: Instance Metadata",
        "log_sources": [
            {"type": "Instance", "source": "Instance Deletion", "destination": ""},
            {"type": "Instance", "source": "Instance Metadata", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "CloudTrail Event", "location": "AWS Logs", "identify": "TerminateInstances"},
            {"type": "Audit Entry", "location": "GCP Cloud Audit Logs", "identify": "gcloud compute instances delete"}
        ],
        "destination_artifacts": [
            {"type": "Deleted Instance Record", "location": "Cloud Monitoring Logs", "identify": "Termination event with no cleanup context"},
            {"type": "Anomalous User Operation", "location": "IAM Logs", "identify": "Deletion by unknown or new identity"}
        ],
        "detection_methods": [
            "Monitor for instance deletions not linked to approved operations",
            "Correlate deletion activity with recent instance creation or snapshot use",
            "Alert on deletion of high-value or sensitive workload VMs"
        ],
        "apt": ["APT29", "UNC2452", "MuddyWater"],
        "spl_query": [
            "index=cloud_logs eventName=\"TerminateInstances\"\n| stats count by userIdentity.arn, sourceIPAddress, requestParameters.instanceId, eventTime"
        ],
        "hunt_steps": [
            "Identify recent instance deletions across cloud accounts",
            "Review audit trails for user actions prior to deletion",
            "Search for signs of staging or data exfiltration activity before termination"
        ],
        "expected_outcomes": [
            "Flag unauthorized or suspicious instance deletions",
            "Map attacker workflow: create > snapshot mount > delete",
            "Correlate deletions with IAM role misuse or lateral movement"
        ],
        "false_positive": "Routine maintenance, auto-scaling, or decommissioning activities can produce similar logs. Validate deletions against CI/CD pipeline logs or change records.",
        "clearing_steps": [
            "Restore deleted instance from snapshot if available",
            "Quarantine IAM accounts involved in deletion",
            "Initiate forensic review of attached storage or logs"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1578", "example": "Deletion of ephemeral cloud VMs post exfiltration"}
        ],
        "watchlist": [
            "TerminateInstances API Calls",
            "Delete actions after snapshot activity",
            "VM deletions performed by newly created IAM roles"
        ],
        "enhancements": [
            "Enable guardrails that prevent immediate permanent deletion",
            "Enforce log retention independent of instance state",
            "Tag high-value workloads for alerting on deletion"
        ],
        "summary": "Cloud instance deletion is used by attackers to erase evidence of prior actions. Tracking instance lifecycle events and correlating deletions with suspicious behavior helps identify this technique.",
        "remediation": "Use immutable logging, enforce tagging and retention policies, and require approval workflows for instance termination.",
        "improvements": "Build automated alerts for deletion chains following snapshot mounts, and maintain off-instance logs for long-term forensic support.",
        "mitre_version": "16.1"
    }
