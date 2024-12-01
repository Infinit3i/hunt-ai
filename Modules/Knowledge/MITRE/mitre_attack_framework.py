def get_content():
    """
    Returns structured content for the MITRE ATT&CK Framework.
    """
    return [
        {
            "title": "Overview",
            "content": """
- Framework for categorizing adversary tactics and techniques.
- Based on real-world observations.
            """
        },
        {
            "title": "Persistence Categories",
            "content": """
- Registry Keys, Scheduled Tasks.
- Services, Startup Folders.
            """
        },
        {
            "title": "Application",
            "content": """
- Helps identify TTPs used in attacks.
- Aligns defensive strategies with adversary behavior.
            """
        }
    ]
