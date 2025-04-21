def get_content():
    return {
        "id": "T1578.002",
        "url_id": "T1578/002",
        "title": "Modify Cloud Compute Infrastructure: Create Cloud Instance",
        "description": "Adversaries may create new cloud compute instances to evade detection or access data in more permissive environments. This technique enables attackers to avoid controls on existing instances by spawning new virtual machines (VMs) with altered configurations. Common misuse includes creating an instance, mounting snapshots from other volumes, and applying relaxed policies to exfiltrate data or stage files remotely.",
        "tags": ["cloud", "evasion", "AWS", "Azure", "GCP", "runinstances", "create-vm"],
        "tactic": "Defense Evasion",
        "protocol": "",
        "os": "IaaS",
        "tips": [
            "Monitor VM creation events for unknown or low-trust users.",
            "Track snapshot access patterns that precede instance creation.",
            "Use allowlists and policy-based controls for who can create compute resources."
        ],
        "data_sources": "Instance: Instance Creation, Instance: Instance Metadata",
        "log_sources": [
            {"type": "Instance", "source": "Instance Creation", "destination": ""},
            {"type": "Instance", "source": "Instance Metadata", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "CloudTrail Event", "location": "AWS", "identify": "RunInstances"},
            {"type": "Admin Activity Audit", "location": "GCP", "identify": "gcloud compute instances create"},
            {"type": "Azure Activity Log", "location": "Azure", "identify": "Create Virtual Machine"}
        ],
        "destination_artifacts": [
            {"type": "Mounted Volume Access", "location": "Newly Created VM", "identify": "Snapshot attached"},
            {"type": "IAM Role Binding", "location": "Compute Instance Metadata", "identify": "New or elevated roles"}
        ],
        "detection_methods": [
            "Detect instance creation events outside of approved templates",
            "Alert when instance is created and immediately used for snapshot mount or data staging",
            "Monitor VM creation followed by IAM changes or outbound traffic"
        ],
        "apt": ["Scattered Spider", "UNC3944", "APT29"],
        "spl_query": [
            "index=cloud_logs eventName=\"RunInstances\"\n| stats count by userIdentity.arn, sourceIPAddress, requestParameters.instanceType, eventTime"
        ],
        "hunt_steps": [
            "List new instances created in the past 7 days",
            "Correlate with snapshot mounts or volume attachments",
            "Check IAM activity around the time of creation"
        ],
        "expected_outcomes": [
            "Detect unauthorized compute resource usage",
            "Reveal adversary attempts to bypass existing firewall or IAM policies",
            "Uncover VM creation chains tied to snapshot exploration or staging"
        ],
        "false_positive": "Automated scaling systems or CI/CD pipelines may create VMs as part of normal operations. Use tags or known service account activity to reduce noise.",
        "clearing_steps": [
            "Terminate unauthorized instances",
            "Detach and secure any mounted volumes or snapshots",
            "Review IAM policies and block further instance creation from compromised identities"
        ],
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1578", "example": "Adversary-created VM to bypass logging policies"}
        ],
        "watchlist": [
            "RunInstances events from low-trust IAM roles",
            "Instance creation outside business hours",
            "New VM created and used to mount snapshot within 5 minutes"
        ],
        "enhancements": [
            "Enforce identity-based restrictions on compute creation",
            "Apply default deny egress firewall rules to new instances",
            "Alert when VM is created without a valid deployment tag"
        ],
        "summary": "Creating new compute instances allows attackers to evade detection by operating outside expected infrastructure. These instances can be used to mount snapshots, exfiltrate data, or run tools in isolation.",
        "remediation": "Restrict who can create cloud compute instances and require justification with infrastructure-as-code approval. Review IAM roles for least privilege.",
        "improvements": "Integrate automatic validation of instance origin, and baseline expected compute inventory to detect drift.",
        "mitre_version": "16.1"
    }
