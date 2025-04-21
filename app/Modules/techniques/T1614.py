def get_content():
    return {
        "id": "T1614",
        "url_id": "T1614",
        "title": "System Location Discovery",
        "description": "Adversaries may attempt to determine the geographical location of a compromised system as part of their discovery efforts. This can influence follow-on behavior, such as whether the malware continues execution, exfiltrates data, or alters its payload. Methods for determining location include querying system time zone, keyboard layout, language preferences, IP-based geolocation, and calling system APIs like `GetLocaleInfoW`. In cloud environments, adversaries may retrieve instance metadata, such as availability zone data, from cloud provider services like AWS or Azure metadata APIs. Additionally, online IP lookup services may be used to geolocate external-facing IPs.",
        "tags": ["geolocation", "time zone", "locale", "language", "metadata", "IP address"],
        "tactic": "Discovery",
        "protocol": "",
        "os": "IaaS, Linux, Windows, macOS",
        "tips": [
            "Correlate geolocation activity with early infection stages or branching logic in malware.",
            "Review cloud logs for access to instance metadata services from internal IPs.",
            "Look for invocations of locale/time zone APIs from suspicious processes."
        ],
        "data_sources": "Command: Command Execution, Process: OS API Execution, Process: Process Creation",
        "log_sources": [
            {"type": "Command", "source": "Auditd, EDR, Sysmon", "destination": ""},
            {"type": "Process", "source": "Sysmon, cloud telemetry", "destination": ""},
            {"type": "API Call", "source": "ETW, Debug logs", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "API Call", "location": "Windows System DLLs", "identify": "GetLocaleInfoW, GetTimeZoneInformation"},
            {"type": "Command Execution", "location": "Shell/Terminal", "identify": "tzutil, date, locale"},
            {"type": "Cloud API", "location": "Instance Metadata URL", "identify": "AWS/Azure metadata endpoints"},
            {"type": "Web Request", "location": "External IP Lookup", "identify": "ip-api.com, ipinfo.io"}
        ],
        "destination_artifacts": [
            {"type": "API Response", "location": "Process Memory", "identify": "Time zone, locale, region info"},
            {"type": "HTTP Response", "location": "Web Service", "identify": "Geo-IP results"},
            {"type": "Metadata", "location": "Cloud Instance Metadata", "identify": "Availability Zone"}
        ],
        "detection_methods": [
            "Monitor suspicious use of locale/time zone commands or APIs.",
            "Log cloud instance metadata API queries internally.",
            "Track traffic to geolocation services from internal endpoints.",
            "Use behavioral analytics to flag pre-check conditions used for selective targeting."
        ],
        "apt": [
            "Ragnar Locker: Used GetLocaleInfoW and time zone checks to avoid execution on specific regional targets.",
            "Transparent Tribe: Leveraged IP geolocation services for targeting.",
            "Gootloader: Embedded region-checking logic to determine malware branching behavior."
        ],
        "spl_query": "index=sysmon EventCode=1 (CommandLine=*tzutil* OR CommandLine=*locale* OR CommandLine=*curl* AND *ip-api.com*) \n| stats count by Computer, CommandLine, ParentProcessName",
        "spl_rule": "https://research.splunk.com/detections/tactics/discovery/",
        "elastic_rule": "https://grep.app/search?f.repo=elastic%2Fdetection-rules&q=T1614",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1614",
        "hunt_steps": [
            "Look for calls to `GetLocaleInfoW` or similar APIs in memory or logs.",
            "Scan process creation events for geo-location service queries.",
            "Investigate access to AWS or Azure instance metadata from suspicious hosts.",
            "Review malware or scripts for hardcoded location filtering logic."
        ],
        "expected_outcomes": [
            "Detection of malware designed to avoid certain regions.",
            "Identification of geo-aware payloads or malware staging behavior.",
            "Insight into attacker targeting logic and region-specific bypasses."
        ],
        "false_positive": "Legitimate software may query location for localization, support, or analytics purposes.",
        "clearing_steps": [
            "Restrict outbound requests to known geo-IP APIs.",
            "Audit cloud metadata API access within VM/instance environments.",
            "Apply detection rules to flag API calls from unsigned or suspicious binaries."
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1614 (System Location Discovery)", "example": "Calling GetLocaleInfoW to determine system region before launching payload."}
        ],
        "watchlist": [
            "Web access to ip-api.com, ipinfo.io, or similar from endpoints.",
            "Access to AWS metadata endpoints (169.254.169.254) outside normal provisioning.",
            "Locale or region API usage from uncommon processes."
        ],
        "enhancements": [
            "Implement behavioral triggers for cloud metadata access patterns.",
            "Create watchlists for known geo-IP lookups and alert on abnormal usage.",
            "Emulate different language/region setups in sandbox to identify evasion behavior."
        ],
        "summary": "System Location Discovery techniques help adversaries make targeting decisions and avoid scrutiny by identifying the region of a host. This may involve querying OS APIs, cloud metadata endpoints, or external IP geolocation services.",
        "remediation": "Audit processes that retrieve system location data and restrict access to unnecessary external IP-lookup services. Review cloud metadata exposure configurations.",
        "improvements": "Enhance detection capabilities with signatureless heuristics for geolocation behavior. Consider honeytoken values in metadata responses to detect probing.",
        "mitre_version": "16.1"
    }
