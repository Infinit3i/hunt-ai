def get_content():
    return {
        "id": "T1530",  # Tactic Technique ID
        "url_id": "1530",  # URL segment for technique reference
        "title": "Data from Cloud Storage",  # Name of the attack technique
        "description": "Adversaries may access data from cloud storage solutions, such as Amazon S3, Azure Storage, or Google Cloud Storage, potentially exposing sensitive information through misconfigurations or stolen credentials.",  # Simple description
        "tags": [
            "Data from Cloud Storage",
            "Cloud Storage",
            "IaaS",
            "SaaS",
            "Office Suite",
            "Misconfiguration",
            "Access Control",
            "Amazon S3 Security",
            "Microsoft Azure Storage Security",
            "Google Cloud Storage Best Practices"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "IaaS, Office Suite, SaaS",  # Targeted operating systems/environments
        "tips": [
            "Monitor for unusual queries to the cloud provider's storage service",
            "Look for activity originating from unexpected or unauthorized sources",
            "Watch for failed attempts to access a specific object followed by privilege escalation and successful access"
        ],
        "data_sources": "Cloud Service: Cloud Service Metadata, Cloud Storage: Cloud Storage Access",
        "log_sources": [
            {
                "type": "Cloud Service",
                "source": "Cloud Service Logs",
                "destination": "SIEM"
            },
            {
                "type": "Cloud Storage",
                "source": "Storage Access Logs",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Cloud Storage Object",
                "location": "Cloud environment",
                "identify": "Potentially misconfigured or stolen credentials granting unauthorized access"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Data",
                "location": "Local or external environment",
                "identify": "Exfiltrated files from cloud storage"
            }
        ],
        "detection_methods": [
            "Analyze logs for anomalous requests to cloud storage services",
            "Detect repeated failed attempts followed by successful accesses under the same account",
            "Look for evidence of public or overly broad access permissions"
        ],
        "apt": [
            "APT41",
            "Iran-Based Actor",
            "Scattered Spider"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Review cloud storage access logs for abnormal geolocation or IP patterns",
            "Check for any publicly accessible buckets or containers with sensitive data",
            "Identify newly created accounts or API keys with unexpected permissions"
        ],
        "expected_outcomes": [
            "Detection of misconfigured cloud storage objects exposed to unauthorized access",
            "Identification of stolen or leaked credentials being used to access cloud data",
            "Discovery of unusual data retrieval or exfiltration patterns"
        ],
        "false_positive": "Legitimate business operations, such as new employees or temporary contractors, may generate unexpected access patterns. Validate context and purpose of access.",
        "clearing_steps": [
            "Reconfigure cloud storage to enforce proper access controls (e.g., remove public access)",
            "Rotate or revoke leaked credentials and enforce MFA where applicable",
            "Conduct a thorough audit of cloud IAM policies to ensure least privilege"
        ],
        "mitre_mapping": [
            {
                "tactic": "Exfiltration",
                "technique": "Exfiltration Over Web Service (T1567.002)",
                "example": "Adversaries exfiltrate data from cloud storage buckets or SaaS platforms via web service calls"
            }
        ],
        "watchlist": [
            "Unexpected source IPs or geolocations accessing cloud storage",
            "Sudden spikes in read operations or data downloads",
            "Access attempts to cloud storage objects with sensitive file names or large file sizes"
        ],
        "enhancements": [
            "Enable cloud storage logging and alerts for read/write operations on critical data",
            "Use security posture management tools to automatically detect misconfigurations",
            "Implement robust encryption at rest and in transit for stored data"
        ],
        "summary": "Data stored in cloud environments is often a prime target for adversaries, who may exploit misconfigurations or stolen credentials to collect and exfiltrate sensitive information.",
        "remediation": "Ensure cloud storage is properly configured with least privilege and restricted access, monitor logs for suspicious activity, and enforce strong identity and access management controls.",
        "improvements": "Regularly audit permissions, apply continuous monitoring of cloud storage services, and train personnel on secure configuration practices to minimize the risk of exposure."
    }
