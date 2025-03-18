def get_content():
    return {
        "id": "T1584.005",
        "url_id": "1584/005",
        "title": "Compromise Infrastructure: Botnet",
        "description": 'Adversaries may compromise numerous third-party systems to form a botnet that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks.(Citation: Norton Botnet) Instead of purchasing or renting a botnet from a booter/stresser service, adversaries may build their own by compromising numerous third-party systems.(Citation: Imperva DDoS for Hire) Adversaries may also conduct a takeover of an existing botnet, such as redirecting bots to adversary-controlled C2 servers.(Citation: Dell Dridex Oct 2015) With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale Phishing or Distributed Denial of Service (DDoS).(Citation: Novetta-Axiom)(Citation: NCSC Cyclops Blink February 2022)(Citation: CISA AA24-038A PRC Critical Infrastructure February 2024)',
        "tags": [
            "resource-development",
            "botnet",
            "compromise-infrastructure"
        ],
        "tactic": "Resource Development",
        "protocol": "N/A",
        "os": "N/A",
        "tips": [
            "Monitor outbound network traffic for unusual spikes or patterns that may indicate a botnet.",
            "Implement intrusion detection/prevention systems (IDS/IPS) to detect and block known malicious botnet signatures.",
            "Maintain robust patching and vulnerability management programs to reduce the risk of mass exploitation.",
            "Leverage threat intelligence to identify known botnet command and control (C2) infrastructure and block or monitor those indicators."
        ],
        "data_sources": "Network Traffic, Endpoint, IDS/IPS",
        "log_sources": [
            {
                "type": "Network Traffic",
                "source": "Firewall or IDS Logs",
                "destination": "SIEM"
            },
            {
                "type": "Endpoint",
                "source": "EDR or Sysmon Logs",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Host",
                "location": "Numerous compromised third-party systems",
                "identify": "Infected or taken over by adversaries to form part of a botnet"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Botnet",
                "location": "Adversary-controlled C2 infrastructure",
                "identify": "Used to coordinate attacks (e.g., DDoS, large-scale phishing)"
            }
        ],
        "detection_methods": [
            "Look for significant increases in outbound traffic to unknown or suspicious IP addresses",
            "Correlate endpoint alerts for malware consistent with botnet infections",
            "Monitor for repeated connection attempts to known botnet C2 domains or IP ranges",
            "Analyze network flow data for patterns of scanning or exploit attempts from internal hosts"
        ],
        "apt": [
            "Axiom",
            "Cyclops Blink"
        ],
        "spl_query": [
            "sourcetype=network_traffic direction=outbound blocked=false \n| stats count by src_ip, dest_ip \n| where count > 100"
        ],
        "hunt_steps": [
            "Collect and centralize firewall, IDS, and endpoint logs for suspicious connection attempts.",
            "Identify internal hosts with repeated or anomalous external connections indicative of botnet C2 traffic.",
            "Check threat intelligence feeds for any IPs or domains flagged as botnet controllers.",
            "Investigate potential infections by scanning hosts that exhibit signs of mass exploitation or malicious traffic generation."
        ],
        "expected_outcomes": [
            "Detection of large-scale malicious campaigns (e.g., DDoS, phishing) originating from compromised systems.",
            "Identification of hosts within the environment participating in botnet activity.",
            "Early warning and disruption of adversary operations relying on a botnet for attacks."
        ],
        "false_positive": "High-volume legitimate network processes (e.g., software updates, distributed computing tasks) may appear similar to botnet traffic. Baseline normal activity for accurate detection.",
        "clearing_steps": [
            "Identify and isolate infected systems participating in the botnet.",
            "Remove malicious software or reimage compromised hosts as necessary.",
            "Block known malicious domains/IP addresses and update network policies to prevent re-infection.",
            "Investigate potential root causes (e.g., unpatched vulnerabilities) and remediate to prevent future compromises."
        ],
        "mitre_mapping": [
            {
                "tactic": "Initial Access",
                "technique": "Phishing (T1566)",
                "example": "Adversaries may use compromised bots to send large-scale phishing emails."
            },
            {
                "tactic": "Impact",
                "technique": "Network Denial of Service (T1498)",
                "example": "Botnets can launch DDoS attacks against target infrastructure."
            }
        ],
        "watchlist": [
            "Outbound traffic to known malicious or high-risk IP ranges",
            "Sudden changes in traffic patterns from multiple internal hosts",
            "Repeated failed attempts to connect to external services or scanning behavior"
        ],
        "enhancements": [
            "Implement sinkholing techniques to redirect botnet traffic for analysis and containment.",
            "Use automated threat intelligence correlation to detect known botnet C2 indicators in real-time.",
            "Enable advanced analytics (e.g., machine learning) to identify abnormal host-to-host communication patterns."
        ],
        "summary": "Compromising numerous third-party systems into a botnet enables adversaries to conduct large-scale malicious campaigns, including phishing and DDoS, while obscuring attribution and complicating detection.",
        "remediation": "Isolate and remediate infected hosts, block malicious domains/IPs, apply security patches, and strengthen monitoring to prevent reinfection or further adversary leverage of a botnet.",
        "improvements": "Deploy continuous network traffic analysis, adopt zero-trust segmentation to limit lateral movement, and keep updated threat intelligence to quickly identify and contain botnet-related activity."
    }
