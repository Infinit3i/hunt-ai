def get_content():
    """
    Returns structured content for case studies and specific incidents.
    """
    return [
        {
            "title": "Golden Ticket Attack",
            "content": """
- Resolution: Change `krbtgt` account password twice.
            """
        },
        {
            "title": "SQL Injection Defense",
            "content": """
- Parameterized queries as the most effective mitigation.
            """
        },
        {
            "title": "Cloud Security Issues",
            "content": """
- Misconfigured buckets: Files can be enumerated and downloaded.
- IMDSv2: Mitigates SSRF exploitation.
            """
        }
    ]
