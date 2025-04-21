def get_content():
    return {
        "id": "T1578.005",
        "url_id": "T1578/005",
        "title": "Modify Cloud Compute Configurations",
        "description": "Adversaries may modify cloud compute configurations such as quotas, service regions, or tenant-wide policies to enable malicious operations while evading detection. These changes may allow for expanded resource use (e.g., VM size, region availability) or bypass limitations set to control cost and security posture. These modifications do not directly alter running instances but can enable follow-on actions such as resource hijacking or staging infrastructure in less-monitored regions.",
        "tags": ["cloud", "azure", "aws", "quota-abuse", "resource-hijacking", "tenant-policy", "region-evasion"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "IaaS",
        "tips": [
            "Continuously monitor changes to cloud quotas, policies, and resource configurations.",
            "Alert on approval workflows or tickets requesting suspicious quota increases.",
            "Restrict unused regions and tightly scope roles authorized to modify tenant policies."
        ],
        "data_sources": "Cloud Service: Cloud Service Modification",
        "log_sources": [
            {"type": "Cloud Service", "source": "Cloud Service Modification", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "API Request", "location": "Cloud Audit Logs", "identify": "Quota Increase or Policy Modification"},
            {"type": "Role Change", "location": "IAM Events", "identify": "Assignment of privileges for quota management"}
        ],
        "destination_artifacts": [
            {"type": "Quota Adjustment", "location": "Compute Configuration", "identify": "Increased CPU/GPU limits"},
            {"type": "Policy Change", "location": "Cloud Tenant Settings", "identify": "Disabled restriction on VM size or region"}
        ],
        "detection_methods": [
            "Monitor cloud audit logs for quota increase requests",
            "Track modifications to Azure Policy or AWS Organization SCPs",
            "Alert on enabling access to unsupported regions"
        ],
        "apt": ["UNC3886", "Lazarus Group", "APT41"],
        "spl_query": [
            "index=cloud_audit eventName IN (\"UpdatePolicy\", \"RequestQuotaIncrease\", \"EnableRegion\")\n| stats count by user, eventName, requestParameters, sourceIPAddress"
        ],
        "hunt_steps": [
            "Query for unexpected region enablement events or service expansion approvals",
            "Check for escalated privileges tied to compute administration roles",
            "Validate whether tenant-wide policy changes align with business justification"
        ],
        "expected_outcomes": [
            "Identification of modified cloud compute configurations enabling evasive resource usage",
            "Visibility into abuse of service quotas or policy settings",
            "Early detection of resource hijacking attempts masked as legitimate scaling activity"
        ],
        "false_positive": "Legitimate scaling operations or internal IT requests for capacity increases may mimic adversary behavior. Always verify business context or change ticket alignment.",
        "clearing_steps": [
            "Revert suspicious quota or policy changes",
            "Lock unused regions and restrict resource scaling",
            "Rotate admin credentials and investigate associated activity"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1578", "example": "Quota increases requested to support unauthorized compute"},
            {"tactic": "Resource Hijacking", "technique": "T1496", "example": "Leveraged expanded quotas to mine cryptocurrency without impacting monitored instances"}
        ],
        "watchlist": [
            "Quota Increase Requests",
            "Azure Policy Alterations",
            "Unexpected Enablement of Unused Cloud Regions"
        ],
        "enhancements": [
            "Integrate quota modification alerts with security orchestration platforms",
            "Map allowed resource configurations and alert on divergence",
            "Use anomaly detection for VM count spikes or region drift"
        ],
        "summary": "Adversaries may exploit cloud service configurations to stealthily expand compute usage or bypass policy restrictions. Modifying quotas and settings enables them to operate at scale without immediate detection.",
        "remediation": "Apply strict role-based access controls (RBAC), monitor for quota increase activity, disable unused regions, and enforce approval workflows.",
        "improvements": "Build dashboards for cloud service configuration drift and enable continuous monitoring of policy, region, and quota changes.",
        "mitre_version": "16.1"
    }
