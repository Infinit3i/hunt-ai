def get_content():
    return {
        "id": "T1204.003",
        "url_id": "T1204/003",
        "title": "User Execution: Malicious Image",
        "description": "Adversaries may rely on a user running a malicious image to facilitate execution.",
        "tags": ["Execution", "Malicious Image", "Cloud", "Container", "IaaS", "Cryptomining", "Backdoor"],
        "tactic": "Execution",
        "protocol": "Docker, OCI, AWS AMI, Azure Image, GCP Image",
        "os": "Containers, IaaS",
        "tips": [
            "Use signed images and content trust mechanisms (e.g., Docker Content Trust, Azure Content Trust).",
            "Avoid using unverified or public registry images without scanning.",
            "Set up runtime scanning and behavioral monitoring for new containers and instances."
        ],
        "data_sources": "Application Log, Command, Container, Image, Instance",
        "log_sources": [
            {"type": "Image", "source": "Container Registry Logs", "destination": ""},
            {"type": "Container", "source": "Docker Logs", "destination": ""},
            {"type": "Instance", "source": "Cloud Deployment Logs", "destination": ""},
            {"type": "Command", "source": "Shell History or Audit Logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Image Manifest", "location": "Public or Private Registry", "identify": "Backdoored images with malicious startup commands"},
            {"type": "Container Creation Logs", "location": "Runtime Audit Logs", "identify": "Containers created from unknown/unverified images"}
        ],
        "destination_artifacts": [
            {"type": "Process Execution", "location": "Running container or instance", "identify": "Unauthorized cryptominers or C2 tools"},
            {"type": "Command History", "location": "/root/.bash_history or shell logs", "identify": "Initial commands executed from image ENTRYPOINT or CMD"}
        ],
        "detection_methods": [
            "Monitor for containers running images not found in approved image allowlists",
            "Detect anomaly behavior such as unexpected outbound connections or cryptomining",
            "Correlate deployment time with image source and scan results"
        ],
        "apt": [
            "TeamTNT", "Lazarus Group", "Wizard Spider"
        ],
        "spl_query": [
            "index=containers source=image_registry AND NOT image_name IN (\"trusted_image1\", \"trusted_image2\")\n| stats count by image_name, registry, source_ip",
            "index=docker_logs event=container_start image=* | search command=\"*xmrig*\" OR command=\"*wget*\" OR command=\"*bash*\""
        ],
        "hunt_steps": [
            "Identify all recently pulled and deployed container/instance images",
            "Match against known-good approved image inventory",
            "Perform static/dynamic analysis of suspicious images"
        ],
        "expected_outcomes": [
            "Detection of backdoored or tampered cloud/container images",
            "Unauthorized software (e.g., cryptominers, reverse shells) executed within container scope"
        ],
        "false_positive": "Custom or test images used in development may trigger alerts—validate with dev teams.",
        "clearing_steps": [
            "Stop and remove affected containers: docker stop <id> && docker rm <id>",
            "Delete the malicious image: docker rmi <image_name>",
            "Block the registry or repository where image originated",
            "Audit IAM permissions to ensure only trusted users can deploy images"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1608.001", "example": "Upload of malicious AMIs or Docker images to public repositories"},
            {"tactic": "Defense Evasion", "technique": "T1036.005", "example": "Images masquerade as legitimate by name similarity"}
        ],
        "watchlist": [
            "New container starts from previously unseen images",
            "Deployment of instances from non-approved cloud image templates",
            "High CPU utilization by containers (cryptomining indicator)"
        ],
        "enhancements": [
            "Use registry content trust and scanning (e.g., Trivy, Clair)",
            "Limit registry pull access to verified sources only",
            "Tag and classify all internal images for validation"
        ],
        "summary": "Malicious cloud and container images can be uploaded and executed by users, bypassing traditional phishing methods and allowing code execution via compromised infrastructure components.",
        "remediation": "Remove the affected images, implement trusted registry policies, and train users to avoid using unverified public images.",
        "improvements": "Automate detection of new image deployments, enforce image signing, and validate runtime behavior in containerized environments.",
        "mitre_version": "16.1"
    }
