def get_content():
    """
    Returns structured content for general security best practices.
    """
    return [
        {
            "title": "Endpoint Security",
            "content": """
- Application allow lists to prevent unauthorized execution.
- Multi-factor authentication for critical accounts.
            """
        },
        {
            "title": "Network Security",
            "content": """
- Default deny for outbound traffic.
- Monitor SMB and other protocols for misuse.
            """
        },
        {
            "title": "Incident Response",
            "content": """
- First steps: Verify the incident and scope its impact.
- Root cause analysis to prevent recurrence.
            """
        }
    ]
