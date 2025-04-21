def get_content():
    return {
        "id": "T1588.007",
        "url_id": "T1588/007",
        "title": "Obtain Capabilities: Artificial Intelligence",
        "description": "Adversaries may obtain access to generative artificial intelligence tools, such as large language models (LLMs), to aid various techniques during targeting. These tools may be used to inform, bolster, and enable a variety of malicious tasks including conducting reconnaissance, creating basic scripts, assisting social engineering, and even developing payloads. For example, by utilizing a publicly available LLM an adversary is essentially outsourcing or automating certain tasks to the tool. Using AI, the adversary may draft and generate content in a variety of written languages to be used in phishing or phishing for information campaigns. The same publicly available tool may further enable vulnerability or other offensive research supporting capability development. AI tools may also automate technical tasks by generating, refining, or otherwise enhancing malicious scripts and payloads.",
        "tags": ["resource-development", "ai", "llm", "malware-automation", "phishing"],
        "tactic": "Resource Development",
        "protocol": "HTTPS, API",
        "os": "Any",
        "tips": [
            "Monitor for outbound connections to known LLM or AI platforms from sensitive environments",
            "Inspect for programmatic usage of AI services for script generation",
            "Create alerts for domain-specific prompts tied to phishing or offensive security tooling"
        ],
        "data_sources": "Cloud Service, Command, Application Log, Internet Scan, Web Credential",
        "log_sources": [
            {"type": "Cloud Service", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "Web Credential", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Clipboard Data", "location": "Browser session cache", "identify": "Prompt injections or stolen LLM-generated content"},
            {"type": "Event Logs", "location": "Application Logs", "identify": "Use of LLMs via CLI or scripting interfaces"}
        ],
        "destination_artifacts": [
            {"type": "Network Connections", "location": "Firewall or proxy logs", "identify": "Outbound access to AI platform APIs"},
            {"type": "Sysmon Logs", "location": "Event ID 1", "identify": "Tool execution involving API access or automation frameworks"}
        ],
        "detection_methods": [
            "Detect API keys or prompt-based requests to public AI platforms",
            "Monitor for large prompt volumes originating from internal users or scripts",
            "Track behavioral anomalies in scripts and automation toolchains"
        ],
        "apt": ["Unknown (Technique emerging and used across threat sectors)"],
        "spl_query": [
            "index=proxy sourcetype=web url=*openai* OR url=*claude* OR url=*bard*\n| stats count by src_ip, url",
            "index=sysmon EventCode=1 CommandLine=*curl* OR CommandLine=*requests* AND CommandLine=*api.openai.com*\n| stats count by User, CommandLine"
        ],
        "hunt_steps": [
            "Query for API access patterns to known LLM endpoints",
            "Search for curl or Python requests to AI domains",
            "Trace scripting activity generating phishing or payload content"
        ],
        "expected_outcomes": [
            "Identification of adversarial use of public AI tools for capability enhancement",
            "Early warning of content automation or phishing campaigns fueled by AI"
        ],
        "false_positive": "Legitimate use of LLMs by developers, data scientists, or analysts—validate by role and usage pattern.",
        "clearing_steps": [
            "Revoke or rotate any leaked API keys to LLM platforms",
            "Delete prompt logs and temporary output files",
            "Audit scripting environments that accessed AI tools"
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-phishing"],
        "mitre_mapping": [
            {"tactic": "Reconnaissance", "technique": "T1598", "example": "AI-assisted phishing content generation"},
            {"tactic": "Execution", "technique": "T1059", "example": "LLM-generated scripts used in malware payloads"}
        ],
        "watchlist": [
            "Use of `curl` or Python libraries to contact AI APIs",
            "Excessive network egress to AI domains",
            "Sudden generation of large volumes of novel phishing or malicious code"
        ],
        "enhancements": [
            "Deploy deception content into prompt logs to track malicious prompt reuse",
            "Train classifiers to detect AI-generated phishing emails or scripts"
        ],
        "summary": "This technique documents how adversaries may leverage publicly accessible LLMs or other AI capabilities to assist in reconnaissance, payload development, and phishing preparation. These tools reduce time and skill barriers, increasing the potential for scalable attacks.",
        "remediation": "Limit unsanctioned access to LLMs from internal networks. Monitor for abuse of public AI interfaces. Train staff on AI-driven phishing threats.",
        "improvements": "Integrate AI-aware analytics into DLP and phishing analysis workflows. Create alerts based on prompt signatures or endpoint tool usage.",
        "mitre_version": "16.1"
    }
