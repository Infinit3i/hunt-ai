def get_content():
    """
    Returns structured content for network defense strategies and tools.
    """
    return [
        {
            "title": "Web Proxy Types",
            "content": """
- Open Source: Squid, Nginx, Apache Traffic Server.
- Commercial: Symantec Web Filter, Forcepoint, Zscaler.
            """
        },
        {
            "title": "NetFlow and IPFIX",
            "content": """
- Session data for L3/L4 troubleshooting.
- Enables rapid detection without full packet captures.
            """
        },
        {
            "title": "SOC Essentials",
            "content": """
- Functions: Detection, Auditing, Response, Operations/Maintenance.
- Outsourcing vs. internal teams: Benefits and trade-offs.
            """
        }
    ]
