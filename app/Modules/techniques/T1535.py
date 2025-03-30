def get_content():
    return {
        "id": "T1535",
        "url_id": "T1535",
        "title": "Unused/Unsupported Cloud Regions",
        "description": "Adversaries may deploy infrastructure in unused or unsupported cloud service regions to evade detection. Cloud environments often span multiple global regions, but organizations typically use only a subset of them. If logging, alerting, or monitoring is not enabled in these unused regions, an attacker can operate unnoticed. Some regions may also lack the security services deployed in primary zones, providing attackers an advantage. One common use is illicit cryptocurrency mining via resource hijacking.",
        "tags": ["cloud", "evasion", "AWS", "regions", "crypto mining", "T1535"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "IaaS",
        "tips": [
            "Audit and monitor activity across all cloud regions, not just the ones in production use.",
            "Disable or restrict access to unused cloud regions where possible.",
            "Use anomaly detection rules for unexpected regional instance creation."
        ],
        "data_sources": "Instance: Instance Creation, Instance: Instance Metadata",
        "log_sources": [
            {"type": "Instance", "source": "Cloud Control Plane Logs", "destination": ""},
            {"type": "Instance", "source": "Cloud Monitoring API", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "API Call", "location": "CloudTrail / Audit Log", "identify": "CreateInstance or similar events in regions outside approved geographies"},
            {"type": "Metadata Changes", "location": "Cloud Inventory", "identify": "Instance metadata showing newly provisioned assets in rare regions"}
        ],
        "destination_artifacts": [
            {"type": "Billing Alerts", "location": "Cloud Billing Console", "identify": "Unexpected compute usage spikes in foreign regions"},
            {"type": "Command Execution", "location": "Instance Logs", "identify": "Startup scripts or crypto mining activity in rogue regions"}
        ],
        "detection_methods": [
            "Monitor for resource creation in normally unused regions.",
            "Create anomaly-based thresholds for instances launched in uncommon geographic zones.",
            "Review logs and usage metrics regularly for signs of cryptojacking."
        ],
        "apt": [],
        "spl_query": [
            'index=cloud_logs eventName="RunInstances" OR eventName="CreateInstance"\n| search region!="us-east-1" AND region!="us-west-2"\n| stats count by user, region, instanceType',
            'index=cloud_billing\n| search usageType="BoxUsage:*"\n| stats sum(cost) by region, user\n| where region="unused_region"',
            'index=cloud_api_calls\n| search eventSource="ec2.amazonaws.com" eventName="DescribeRegions"\n| stats count by user, region'
        ],
        "hunt_steps": [
            "Enumerate all cloud regions and check for activity outside of normal usage areas.",
            "Search audit logs for new instance creation in underused or disabled regions.",
            "Correlate with billing data to assess unauthorized compute usage or cost anomalies."
        ],
        "expected_outcomes": [
            "Detection of stealth infrastructure setup in unmonitored regions.",
            "Prevention or removal of adversary-controlled resources in secondary regions.",
            "Improved cloud monitoring posture across all geographical zones."
        ],
        "false_positive": "Legitimate operations during DR testing or global failover scenarios may result in unexpected instance creation.",
        "clearing_steps": [
            "Terminate any unauthorized instances running in unapproved regions.",
            "Disable region access where possible via cloud policy.",
            "Review IAM roles and permissions for overprovisioning."
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1535", "example": "Creating EC2 instances in unmonitored AWS regions to evade detection while performing cryptojacking"}
        ],
        "watchlist": [
            "Users provisioning resources in non-standard regions",
            "Accounts querying region capabilities via DescribeRegions API",
            "Unexpected billing increases from obscure regions"
        ],
        "enhancements": [
            "Integrate cloud CSPM tools to visualize unused regions.",
            "Alert on IAM activity tied to region provisioning or modification.",
            "Automate teardown of noncompliant infrastructure via Lambda or similar."
        ],
        "summary": "Unused or unsupported cloud regions offer attackers a hiding spot to operate without alerting standard security systems. This is especially useful in resource hijacking operations or staging infrastructure for further attack.",
        "remediation": "Audit cloud resource distribution, restrict access to unused regions, and monitor for drift or rogue activity in those areas.",
        "improvements": "Include all regions in default security monitoring, and enforce policy-driven usage boundaries.",
        "mitre_version": "16.1"
    }
