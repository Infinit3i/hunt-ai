def get_content():
    return {
        "id": "T1071.005",
        "url_id": "1071/005",
        "title": "Application Layer Protocol: Publish/Subscribe Protocols",
        "description": "Adversaries may communicate using publish/subscribe (pub/sub) application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. Protocols such as MQTT, XMPP, AMQP, and STOMP use a publish/subscribe design, with message distribution managed by a centralized broker. Publishers categorize their messages by topics, while subscribers receive messages according to their subscribed topics. An adversary may abuse publish/subscribe protocols to communicate with systems under their control from behind a message broker while also mimicking normal, expected traffic.",
        "tags": ["Command and Control", "Network Traffic", "Application Layer Protocol"],
        "tactic": "Command and Control",
        "protocol": "MQTT, XMPP, AMQP, STOMP",
        "os": "Linux, Network, Windows, macOS",
        "tips": [
            "Analyze network data for uncommon data flows.",
            "Monitor for excessive publish/subscribe messages from a single source.",
            "Detect unexpected usage of pub/sub protocols in environments where they are not commonly used."
        ],
        "data_sources": "Network Traffic: Network Traffic Content, Network Traffic: Network Traffic Flow",
        "log_sources": [
            {"type": "Network Traffic", "source": "Packet Capture", "destination": "Network Monitor"}
        ],
        "source_artifacts": [
            {"type": "Network Packet", "location": "Inbound/Outbound Traffic", "identify": "Protocol Analysis"}
        ],
        "destination_artifacts": [
            {"type": "Network Packet", "location": "Message Broker", "identify": "Broker Communication"}
        ],
        "detection_methods": ["Traffic Pattern Analysis", "Protocol Anomaly Detection"],
        "apt": ["Mandiant APT1"],
        "spl_query": [
            "| tstats count where index=* AND sourcetype=network_traffic AND protocol IN (MQTT, XMPP, AMQP, STOMP) \n| stats count by src_ip dest_ip protocol"
        ],
        "hunt_steps": [
            "Inspect message brokers for unusual topic subscriptions.",
            "Monitor logs for unauthorized use of pub/sub protocols.",
            "Analyze network traffic for unexpected pub/sub communication."
        ],
        "expected_outcomes": [
            "Detection of unauthorized or suspicious pub/sub protocol usage.",
            "Identification of adversary-controlled communication channels."
        ],
        "false_positive": "Legitimate use of pub/sub protocols in IoT or enterprise environments may generate similar traffic patterns.",
        "clearing_steps": [
            "Block unauthorized access to message brokers.",
            "Restrict pub/sub protocol use to trusted applications.",
            "Implement deep packet inspection for pub/sub traffic."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1071.002", "example": "Application Layer Protocol: File Transfer Protocols"}
        ],
        "watchlist": ["Monitor for unexpected MQTT, XMPP, AMQP, and STOMP usage."],
        "enhancements": ["Improve anomaly detection in pub/sub communication patterns."],
        "summary": "Publish/subscribe protocols can be abused by adversaries to establish hidden communication channels.",
        "remediation": "Restrict unauthorized access to message brokers and enforce strict pub/sub protocol monitoring.",
        "improvements": "Enhance visibility into message broker activities and detect suspicious pub/sub interactions."
    }
