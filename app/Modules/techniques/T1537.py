def get_content():
    return {
        "id": "T1537",
        "url_id": "T1537",
        "title": "Transfer Data to Cloud Account",
        "description": "Adversaries may exfiltrate sensitive data by moving it to a cloud account under their control within the same service provider. This evasion technique uses internal cloud pathways, such as shared snapshots, anonymous file sharing links, or SAS URIs in Azure, to blend in with normal activity. Since these transfers occur internally, traditional data exfiltration monitoring (e.g., for outbound traffic) may miss them.",
        "tags": ["cloud", "data exfiltration", "EBS snapshot", "Azure SAS", "internal transfer", "T1537"],
        "tactic": "Exfiltration",
        "protocol": "",
        "os": "IaaS, Office Suite, SaaS",
        "tips": [
            "Set alerts for snapshot or file share activities to non-org accounts.",
            "Audit CloudTrail or equivalent for internal transfers.",
            "Correlate data volume anomalies with snapshot creation events."
        ],
        "data_sources": "Cloud Storage: Cloud Storage Creation, Snapshot: Snapshot Creation, Application Log: Application Log Content",
        "log_sources": [
            {"type": "CloudTrail", "source": "AWS", "destination": ""},
            {"type": "Activity Logs", "source": "Azure", "destination": ""},
            {"type": "Audit Logs", "source": "Google Workspace", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Snapshot Creation", "location": "AWS CloudTrail", "identify": "ModifySnapshotAttribute event with external user"},
            {"type": "SAS URL Generation", "location": "Azure Activity Logs", "identify": "Get Snapshot SAS URL"}
        ],
        "destination_artifacts": [
            {"type": "Data Sharing", "location": "Cloud Console / Logs", "identify": "Snapshots or files accessible by external accounts"},
            {"type": "Network Flow", "location": "Cloud Traffic Logs", "identify": "Unusual lateral transfer volume within same provider"}
        ],
        "detection_methods": [
            "Monitor snapshot sharing activity across AWS, Azure, and GCP.",
            "Detect SAS link generation or public file access settings.",
            "Alert on data movement toward unknown VPCs or cloud tenants."
        ],
        "apt": [
            "APT28",  # Referenced via GRU indictment for cloud snapshot activity
            "GOLD IONIC",  # Referenced in Secureworks 2024 reporting
            "RedCurl"  # Referenced by Group-IB in documented data theft cases
        ],
        "spl_query": [
            'index=cloud_logs source="cloudtrail" eventName="ModifySnapshotAttribute"\n| search attributeType="createVolumePermission" AND attributeValue!="ORG_ACCOUNT_ID"',
            'index=azure_logs OperationName="Get Snapshot SAS URL"\n| stats count by callerIpAddress, identity, timestamp',
            'index=cloud_storage\n| search sharing="external" OR visibility="public"\n| stats values(user), count by resourceName'
        ],
        "hunt_steps": [
            "Hunt for externally shared resources (snapshots, buckets, folders).",
            "Query audit logs for inter-account sharing events or link generations.",
            "Review user activity logs for abnormal data access just before sharing."
        ],
        "expected_outcomes": [
            "Detection of data exfiltration paths using cloud-native mechanisms.",
            "Identification of compromised accounts using stealthy sharing features.",
            "Improved visibility into lateral movement via cloud control planes."
        ],
        "false_positive": "Legitimate sharing with external partners or backup accounts. Validation through context (e.g., ticketing system) is recommended.",
        "clearing_steps": [
            "Revoke shared access permissions and invalidate SAS tokens.",
            "Remove any snapshots shared with external principals.",
            "Review IAM role permissions for snapshot and sharing capabilities."
        ],
        "mitre_mapping": [
            {"tactic": "Exfiltration", "technique": "T1537", "example": "APT28 exfiltrated VM snapshots from victim cloud environment into attacker-controlled AWS account"}
        ],
        "watchlist": [
            "Snapshot sharing outside org boundary",
            "Creation of anonymous links or SAS URIs",
            "Use of 'ModifySnapshotAttribute' or Azure Blob SAS APIs"
        ],
        "enhancements": [
            "Implement least privilege on snapshot and storage sharing features.",
            "Block SAS URI generation or external sharing via policy.",
            "Deploy DLP (Data Loss Prevention) tailored for cloud file systems."
        ],
        "summary": "Transferring data internally to attacker-controlled cloud accounts enables stealthy exfiltration. This abuse of cloud-native features like snapshots and shared links avoids traditional network-based detections.",
        "remediation": "Disable public and external sharing by default. Use service control policies and audit tools to monitor and restrict sensitive data replication.",
        "improvements": "Expand DLP coverage into cloud logs and snapshot sharing. Integrate context-aware monitoring for user-based deviations.",
        "mitre_version": "16.1"
    }
