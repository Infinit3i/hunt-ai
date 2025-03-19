def get_content():
    return {
        "id": "T1584.007",  # Tactic Technique ID
        "url_id": "1584/007",  # URL segment for technique reference
        "title": "Compromise Infrastructure: Serverless",  # Name of the attack technique
        "description": (
            "Adversaries may compromise serverless cloud infrastructure (e.g., Cloudflare Workers, AWS Lambda, or Google Apps Scripts) to "
            "host malicious code or proxy traffic. Because traffic to these functions originates from subdomains of trusted cloud providers, "
            "it can be difficult to attribute or detect. Once compromised, serverless functions can be used to relay Command and Control traffic, "
            "launch phishing campaigns, or hide adversary infrastructure."
        ),
        "tags": [
            "serverless compromise",
            "cloud infrastructure",
            "resource development",
            "command and control",
            "proxy"
        ],
        "tactic": "Resource Development",  # Associated MITRE ATT&CK tactic
        "protocol": "HTTP/HTTPS",  # Protocol used in the attack technique
        "os": "N/A",  # Targeted operating systems
        "tips": [
            "Implement strict IAM policies and roles to limit serverless function privileges.",
            "Regularly review serverless code and environment configurations for unauthorized changes.",
            "Monitor for unusual function invocation patterns or suspicious traffic."
        ],
        "data_sources": "Internet Scan",  # Data sources relevant to detection
        "log_sources": [
            {"type": "Internet Scan", "source": "Response Content", "destination": ""}
        ],
        "source_artifacts": [
            {
                "type": "Serverless function code",
                "location": "Cloud provider function runtime",
                "identify": "Check for malicious scripts, modifications, or injected code"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Network Traffic",
                "location": "Inbound/Outbound from serverless functions",
                "identify": "Look for suspicious or anomalous connections"
            }
        ],
        "detection_methods": [
            "Analyze serverless function logs for unexpected code changes or unauthorized invocations.",
            "Correlate network traffic from known cloud provider subdomains with threat intelligence or suspicious patterns.",
            "Monitor for newly created functions or subdomains within your cloud environment."
        ],
        "apt": [],
        "spl_query": [
            "index=network \n| stats count by src_ip, dest_ip, http_host"
        ],
        "hunt_steps": [
            "Review serverless function creation and modification logs for unauthorized changes.",
            "Check for abnormal spikes in invocation metrics or data transfer from functions.",
            "Correlate subdomain usage with known malicious IP addresses or threat actor campaigns."
        ],
        "expected_outcomes": [
            "Detection of compromised serverless functions used as malicious infrastructure.",
            "Identification of suspicious subdomains or unusual function invocation patterns."
        ],
        "false_positive": (
            "Legitimate serverless updates or testing may appear suspicious. Validate with deployment logs and "
            "change management records."
        ),
        "clearing_steps": [
            "Disable or remove malicious serverless functions and associated credentials.",
            "Rotate relevant API keys or access tokens, and enforce MFA for cloud admin accounts.",
            "Review cloud environment permissions and restrict roles to the minimum necessary."
        ],
        "mitre_mapping": [
            {
                "tactic": "Resource Development",
                "technique": "Hide Infrastructure (T1665)",
                "example": "Adversaries can use serverless functions to proxy traffic and disguise infrastructure."
            }
        ],
        "watchlist": [
            "Unexpected serverless functions or subdomains created in your cloud environment.",
            "Significant changes in serverless invocation rates or data egress.",
            "Cloud provider logs indicating repeated failed access attempts or policy violations."
        ],
        "enhancements": [
            "Enable detailed logging and alerting for serverless deployments (including function code changes).",
            "Use web application firewalls (WAF) and cloud access security brokers (CASBs) to monitor serverless traffic.",
            "Regularly audit IAM policies and apply the principle of least privilege."
        ],
        "summary": (
            "By compromising serverless infrastructure, adversaries can leverage the reputation of major cloud providers to "
            "conceal malicious activity and make it more difficult for defenders to attribute or detect suspicious traffic."
        ),
        "remediation": (
            "Restrict permissions, enforce strong authentication and access controls, review code integrity, and "
            "monitor serverless functions for anomalous behavior."
        ),
        "improvements": (
            "Integrate cloud-native threat detection solutions for serverless environments, implement continuous deployment "
            "security checks, and conduct regular threat-hunting exercises focusing on cloud logs and telemetry."
        )
    }
