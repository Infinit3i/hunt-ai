def get_content():
    return {
        "id": "T1525",
        "url_id": "T1525",
        "title": "Implant Internal Image",
        "description": "Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment. This can include injecting backdoors or web shells into images stored within internal registries such as AWS AMIs, Azure Images, GCP Images, or container repositories like Docker Hub. These images, when reused during automated provisioning, can serve as long-term persistent access vectors. Unlike uploading malware to an endpoint, this focuses on placing malicious logic inside base images trusted by the organization.",
        "tags": ["persistence", "cloud", "containers", "image-backdoor", "T1525"],
        "tactic": "Persistence",
        "protocol": "",
        "os": "Containers, IaaS",
        "tips": [
            "Baseline and monitor all container image creation/modification events in internal registries.",
            "Tag and hash trusted images to verify authenticity during provisioning.",
            "Use content trust mechanisms available in Azure, Docker, and other registries."
        ],
        "data_sources": "Image",
        "log_sources": [
            {"type": "Image", "source": "Image Creation", "destination": ""},
            {"type": "Image", "source": "Image Metadata", "destination": ""},
            {"type": "Image", "source": "Image Modification", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Image", "location": "Container Registry", "identify": "Backdoored images with web shells or reverse shells"},
            {"type": "IAM", "location": "Cloud Role Permissions", "identify": "Access allowing 'push' or 'create' actions on images"},
            {"type": "Command", "location": "Cloud CLI/Console", "identify": "Use of `docker push`, `aws ec2 create-image`, or similar tools"}
        ],
        "destination_artifacts": [
            {"type": "Container", "location": "Deployed Instance", "identify": "Containers with unknown or untrusted image sources"},
            {"type": "Audit Logs", "location": "Kubernetes or Docker Logs", "identify": "Anomalous image pulls from unexpected users or services"},
            {"type": "Image Metadata", "location": "Registry", "identify": "Image updates or overwrites with no associated version control notes"}
        ],
        "detection_methods": [
            "Monitor image registries for unauthorized or unapproved image uploads or modifications.",
            "Enable Docker content trust and enforce signed image policies.",
            "Alert on deployments that source from newly created or altered internal images."
        ],
        "apt": [],
        "spl_query": [
            'index=registry_logs action="push" OR action="create" OR action="modify"\n| search user!="ci-bot" image_name="*"',
            'index=kube_audit_logs OR index=docker_logs\n| search event_type="ImagePull" AND image_hash!="approved_hash_list"',
            'index=cloudtrail OR index=gcp.auditlog\n| search eventName="CreateImage" OR methodName="images.insert"'
        ],
        "hunt_steps": [
            "List all container or cloud images created or modified in the past 30 days.",
            "Identify users with permissions to push images and validate if their activity is consistent with expected behavior.",
            "Cross-reference newly modified images with deployment manifests or CI/CD activity logs."
        ],
        "expected_outcomes": [
            "Detection of unauthorized or malicious internal image implants.",
            "Blocking the reuse of infected container or VM images in cloud provisioning.",
            "Attribution of image implants to specific adversarial accounts or automated tools."
        ],
        "false_positive": "Legitimate image updates from CI/CD pipelines or DevOps teams may trigger detections. Validate based on user context, source IP, and CI tooling.",
        "clearing_steps": [
            "Rebuild all production images from verified source code and trusted base images.",
            "Revoke IAM roles or permissions used to implant the malicious image.",
            "Purge all backdoored images and audit systems deployed using them."
        ],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1525", "example": "Implanting web shells in Docker images hosted in private registries"},
            {"tactic": "Execution", "technique": "T1203", "example": "Malicious payloads executed as soon as container image is instantiated"},
            {"tactic": "Defense Evasion", "technique": "T1608.001", "example": "Backdoor is stored in image rather than filesystem to evade endpoint detection"}
        ],
        "watchlist": [
            "Unexpected or large numbers of image uploads to internal registries",
            "Non-CI/CD users pushing updates to base images",
            "New image hashes appearing without versioning or approval history"
        ],
        "enhancements": [
            "Enable image signing and verification using Docker Content Trust or Azure ACR Content Trust.",
            "Use automated security scanners (e.g., Trivy, Clair, Prisma) to scan all image layers before deployment.",
            "Enforce IAM least privilege policies for container registry access."
        ],
        "summary": "Adversaries may implant internal VM or container images in registries to maintain persistence in cloud or hybrid environments. When used in automated provisioning, these images can facilitate long-term access or malware reactivation.",
        "remediation": "Rotate and audit all base images. Rebuild from secure, validated sources. Revoke IAM credentials used during compromise.",
        "improvements": "Adopt SBOMs (Software Bill of Materials) and continuous image scanning. Set up anomaly detection on image registry activity.",
        "mitre_version": "16.1"
    }
