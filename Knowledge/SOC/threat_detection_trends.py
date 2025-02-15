def get_content():
    """
    Returns structured content for threat detection trends and sector-specific insights.
    """
    return [
        {
            "title": "Top Threat Detection Trends",
            "content": """
- Top 20 techniques are common across all industries.
- Most attacks target 10% of T-Codes.
- Detection challenges:
    - Volume of detections.
    - Technique variance and persistence.
            """
        },
        {
            "title": "Industry-Specific Insights",
            "content": """
- **Education**: Email forwarding/hiding rules account for 55% of detections.
- **Manufacturing**: Biggest issue is removable media.
- **Finance & Insurance**: HTML smuggling and distributed component object model attacks.
- **Information Sector**: Unix-based issues, heavy use of Docker, cloud, and servers.
- **Healthcare**: Cron jobs and Unix shell are common targets.
            """
        },
        {
            "title": "Threat Mitigation Focus",
            "content": """
- Focus on hygiene, configuration, data, and systems.
- Techniques most affected:
    - Powershell, registry modification, malicious files, cmd usage.
    - Tool transfers, email hiding, and system utility renaming.
            """
        }
    ]
