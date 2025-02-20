def get_investigate_content():
    """
    Returns the content for the Investigate page.
    """
    return {
        "title": "Investigate",
        "description": "Explore and analyze potential threats using the resources and tools provided.",
        "resources": [
            {"name": "IP", "url": "/investigate/ip"},
            {"name": "Domain", "url": "/investigate/domain"},
            {"name": "File Hash", "url": "/investigate/filehash"},
            {"name": "Malware", "url": "/investigate/malware"}
        ]
    }
