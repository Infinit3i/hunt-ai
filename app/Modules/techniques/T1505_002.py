def get_content():
    return {
        "id": "T1505.002",
        "url_id": "T1505/002",
        "title": "Server Software Component: Transport Agent",
        "description": "Adversaries may abuse Microsoft Exchange transport agents to gain persistent access. These agents operate within the email transport pipeline and can be custom-developed to manipulate or monitor mail flow. Once registered with the Exchange server, a malicious transport agent can perform adversary-defined actions such as capturing email attachments, exfiltrating content, or triggering on specific message conditions.",
        "tags": ["exchange", "email", "transport agent", "persistence", "dotnet", "T1505.002"],
        "tactic": "Persistence",
        "protocol": "SMTP",
        "os": "Windows, Linux",
        "tips": [
            "Audit Exchange transport agent registrations and investigate unrecognized assemblies.",
            "Use strict code signing policies to validate custom transport agents.",
            "Review Exchange Message Tracking Logs for unusual message flow manipulation.",
            "Restrict access to Exchange server roles that allow agent registration."
        ],
        "data_sources": "Application Log, File",
        "log_sources": [
            {"type": "Application Log", "source": "Application Log Content", "destination": ""},
            {"type": "File", "source": "File Creation", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Exchange Configuration", "location": "C:\\Program Files\\Microsoft\\Exchange Server\\V15\\TransportRoles\\agents", "identify": "Custom agent DLLs"},
            {"type": "Registry", "location": "HKLM\\Software\\Microsoft\\ExchangeServer", "identify": "Agent load configuration"},
            {"type": "Event Logs", "location": "Application", "identify": "Agent installation or runtime errors"}
        ],
        "destination_artifacts": [
            {"type": "Email", "location": "Transport Pipeline", "identify": "Delayed, dropped, or exfiltrated emails"},
            {"type": "Log", "location": "Exchange Message Tracking Log", "identify": "Unexpected routing or metadata"},
            {"type": "Network Traffic", "location": "Exchange outbound connection", "identify": "Unusual outbound data from Exchange"}
        ],
        "detection_methods": [
            "Monitor Exchange agent registration paths and compare against approved software baselines.",
            "Analyze message flow using Message Tracking Logs for unexpected changes or new metadata.",
            "Audit filesystem for unauthorized DLLs within Exchange agent folders.",
            "Use behavior analytics to detect anomalous .NET component behavior within Exchange services."
        ],
        "apt": ["APT28", "Turla (via LightNeuron)"],
        "spl_query": [
            'index=exchange_logs sourcetype=ms:ex:agent\n| search "RegisterTransportAgent"\n| stats count by user, agent_name, file_path',
            'index=exchange_logs sourcetype=ms:ex:tracking\n| search recipient_address IN ("*@suspiciousdomain.com")\n| stats count by message_id, recipient_address',
            'index=windows_logs sourcetype=wineventlog_application\n| search "TransportAgent" AND ("error" OR "warning")\n| stats count by host, message'
        ],
        "hunt_steps": [
            "List all currently registered transport agents using `Get-TransportAgent`.",
            "Inspect agent DLL locations and hashes against known-good baselines.",
            "Trace Message Tracking Logs for mail events involving suspicious or unexpected routing behavior.",
            "Monitor for new .NET assemblies loaded by Exchange transport services."
        ],
        "expected_outcomes": [
            "Detection of malicious or unauthorized transport agents.",
            "Uncovering targeted exfiltration through email content or metadata manipulation.",
            "Identification of persistent foothold mechanisms in Exchange infrastructure."
        ],
        "false_positive": "Custom legitimate agents by third-party email filtering solutions may trigger similar signatures. Validate agent source and certificate chains.",
        "clearing_steps": [
            "Unregister malicious agent using `Uninstall-TransportAgent` or `Disable-TransportAgent`.",
            "Delete the associated DLL from the file system.",
            "Restart the Microsoft Exchange Transport service.",
            "Audit logs for potential email exfiltration or data leaks."
        ],
        "clearing_playbook": ["https://learn.microsoft.com/en-us/exchange/transport-agents-exchange-2013-help"],
        "mitre_mapping": [
            {"tactic": "Persistence", "technique": "T1505", "example": "Registering a custom transport agent"},
            {"tactic": "Collection", "technique": "T1114.002", "example": "Capturing email attachments"},
            {"tactic": "Exfiltration", "technique": "T1048", "example": "Using agent to transmit emails externally"}
        ],
        "watchlist": [
            "Unusual DLLs in Exchange transport agent directories",
            "New transport agents appearing outside of approved change windows",
            "Outbound emails with large attachments to external domains",
            "Anomalous .NET runtime behavior within Exchange processes"
        ],
        "enhancements": [
            "Use AppLocker or WDAC to restrict DLL execution paths in Exchange directories.",
            "Enforce secure transport rules and use email DLP solutions.",
            "Integrate Exchange with SIEM for real-time alerting on agent registrations.",
            "Implement continuous integrity monitoring on Exchange server directories."
        ],
        "summary": "Malicious transport agents in Microsoft Exchange can manipulate or monitor email traffic as it passes through the system. These .NET-based components can persist on the server and execute based on adversary-defined triggers, enabling stealthy data exfiltration or ongoing monitoring.",
        "remediation": "Identify and remove unauthorized transport agents, enforce logging and auditing, and limit administrative rights to register agents. Harden Exchange infrastructure with whitelisting and monitoring tools.",
        "improvements": "Deploy monitoring around Exchange's transport pipeline, regularly validate custom agent integrity, and alert on changes to agent registration.",
        "mitre_version": "16.1"
    }
