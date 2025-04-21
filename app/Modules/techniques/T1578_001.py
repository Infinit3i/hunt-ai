def get_content():
    return {
        "id": "T1578.001",
        "url_id": "T1578/001",
        "title": "Modify Cloud Compute Infrastructure: Create Snapshot",
        "description": "Adversaries may create cloud snapshots or backups to evade detection, bypass access restrictions, or facilitate later access. A snapshot captures the state of a volume or disk at a point in time. By creating a snapshot and mounting it to a new instance under adversary-controlled policies, attackers can access sensitive data without directly compromising the original compute resource. This is commonly seen as a precursor to lateral movement or staging data for exfiltration.",
        "tags": ["cloud", "snapshot", "evasion", "AWS", "Azure", "GCP", "forensics"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "IaaS",
        "tips": [
            "Correlate snapshot creation events with user roles and privileges.",
            "Monitor if snapshots are mounted to new VMs with unexpected network policies.",
            "Use automated tagging and anomaly detection to track unexpected backup activities."
        ],
        "data_sources": "Snapshot: Snapshot Creation, Snapshot: Snapshot Metadata",
        "log_sources": [
            {"type": "Snapshot", "source": "Snapshot Creation", "destination": ""},
            {"type": "Snapshot", "source": "Snapshot Metadata", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "CloudTrail Event", "location": "AWS", "identify": "CreateSnapshot"},
            {"type": "Azure Activity Log", "location": "Azure", "identify": "Snapshot Creation"},
            {"type": "GCP Audit Log", "location": "GCP", "identify": "sourceSnapshot parameter in API calls"}
        ],
        "destination_artifacts": [
            {"type": "Mounted Snapshot Volume", "location": "Adversary-controlled VM", "identify": "Attached disk with snapshot origin"},
            {"type": "Network Policy Change", "location": "VM with snapshot", "identify": "SSH/RDP open externally"}
        ],
        "detection_methods": [
            "Detect snapshot creation by low-trust or new identities",
            "Alert when a snapshot is mounted and firewall rules are altered shortly after",
            "Correlate snapshot usage with policy changes or new instance creation"
        ],
        "apt": ["UNC3944", "APT29"],
        "spl_query": [
            "index=cloud_logs eventName=\"CreateSnapshot\"\n| stats count by userIdentity.arn, sourceIPAddress, requestParameters.volumeId, eventTime"
        ],
        "hunt_steps": [
            "Identify snapshots created in the past 7–14 days",
            "Trace which instances they are mounted to",
            "Determine if access policies were altered after mounting"
        ],
        "expected_outcomes": [
            "Detect stealthy access to sensitive volume data",
            "Reveal VM or volume cloning tactics",
            "Highlight attackers attempting to bypass disk encryption or role restrictions"
        ],
        "false_positive": "Legitimate system admins or automated backup tools often create snapshots. Look for changes outside maintenance windows or involving sensitive resource groups.",
        "clearing_steps": [
            "Delete unauthorized snapshots and detach them from instances",
            "Audit and restrict snapshot creation permissions",
            "Rotate affected keys or credentials associated with snapshot activity"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1578", "example": "Mounting snapshot to bypass logging on primary VM"}
        ],
        "watchlist": [
            "Snapshots created by non-admin users",
            "Snapshots linked to new VMs created shortly after",
            "Unexpected IAM roles used to create or mount snapshots"
        ],
        "enhancements": [
            "Implement snapshot tagging and approval workflow",
            "Enable logging for all snapshot creation and attachment operations",
            "Integrate anomaly detection for volume duplication events"
        ],
        "summary": "Snapshot creation is often overlooked in cloud environments and provides adversaries a stealthy way to access data without modifying the original system. Monitoring and strict controls are essential.",
        "remediation": "Enforce role-based snapshot access controls. Monitor and alert on snapshot creation outside approved change windows. Use encryption and key access controls.",
        "improvements": "Standardize tagging and logging of snapshots to facilitate monitoring. Deny snapshot mounting to unauthorized instances by default.",
        "mitre_version": "16.1"
    }
