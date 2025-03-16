def get_content():
    return {
        "id": "T1612",  # Tactic Technique ID
        "url_id": "1612",  # URL segment for technique reference
        "title": "Build Image on Host",  # Name of the attack technique
        "description": "Adversaries may build a container image directly on a host to bypass defenses that monitor for the retrieval of malicious images from a public registry. A remote build request may be sent to the Docker API that includes a Dockerfile that pulls a vanilla base image, such as alpine, from a public or local registry and then builds a custom image upon it. An adversary may take advantage of that build API to build a custom image on the host that includes malware downloaded from their C2 server, and then they may utilize Deploy Container using that custom image. If the base image is pulled from a public registry, defenses will likely not detect the image as malicious since it’s a vanilla image. If the base image already resides in a local registry, the pull may be considered even less suspicious since the image is already in the environment.",  
        "tags": [
            "t1612", 
            "build image on host", 
            "docker attack", 
            "malicious container", 
            "docker security", 
            "defense evasion", 
            "dockerfile exploit", 
            "c2 server malware", 
            "container attack", 
            "docker build abuse"
        ],   
        "tactic": "Defense Evasion",  
        "protocol": "Containers",  
        "os": "Containers",  
        "tips": [
            "Monitor for unexpected Docker image build requests to the Docker daemon on hosts in the environment.",
            "Additionally, monitor for subsequent network communication with anomalous IPs that have never been seen before in the environment that indicate the download of malicious code.",
            "Restrict Docker API access and require authentication for build requests.",
            "Regularly audit images stored in local registries for anomalies."
        ],  
        "data_sources": "Image: Image Creation, Network Traffic: Network Connection Creation, Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow",  
        "log_sources": [  
            {"type": "Docker Daemon Logs", "source": "Image Build Requests", "destination": "Security Logs"}  
        ],  
        "source_artifacts": [  
            {"type": "Docker Image", "location": "/var/lib/docker", "identify": "Locally Built Malicious Images"},  
            {"type": "Network Traffic", "location": "Docker API Logs", "identify": "Remote Build Requests"}  
        ],  
        "destination_artifacts": [  
            {"type": "Log File", "location": "/var/log/docker.log", "identify": "Docker API Request Logs"}  
        ],  
        "detection_methods": ["Monitoring Docker API Requests", "Analyzing Network Traffic for Anomalous Connections"],  
        "apt": ["Team Nautilus Aqua Security"],  
        "spl_query": ["index=docker_logs | search image_build_attempts"],  
        "hunt_steps": ["Check for unauthorized image build requests.", "Analyze network traffic for connections to unknown external hosts after an image build."],  
        "expected_outcomes": ["Detection of unauthorized image build requests used for deploying malicious containers."],  
        "false_positive": "Legitimate DevOps processes may trigger container image builds.",  
        "clearing_steps": ["Restrict Docker API access to trusted users.", "Audit Docker images and remove any unauthorized builds."],  
        "mitre_mapping": [
            {"tactic": "Defense Evasion", "technique": "T1612", "example": "Malicious image build used to deploy backdoors in containers."}
        ],  
        "watchlist": ["Unusual Docker API access", "Network traffic to unknown external IPs post-image build"],  
        "enhancements": ["Implement strict access controls for Docker API.", "Monitor for unexpected image build commands and API requests."],  
        "summary": "Building images directly on a host allows adversaries to bypass defenses monitoring public image repositories, enabling them to deploy malicious containers undetected.",  
        "remediation": "Restrict Docker API access and monitor for anomalous image build activities.",  
        "improvements": "Enhance logging for Docker API events and implement behavior-based anomaly detection for image builds."  
    }
