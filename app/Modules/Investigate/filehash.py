def get_filehash_content():
    """
    Returns content for the File Hash Analysis page.
    """
    return {
        "title": "File Hash Analysis",
        "description": "Explore tools and methods for analyzing file hashes.",
        "resources": [
            {"name": "VirusTotal", "url": "https://www.virustotal.com/gui/home/upload"},
            {"name": "Hybrid Analysis", "url": "https://www.hybrid-analysis.com/"},
            {"name": "Joe Security", "url": "https://www.joesecurity.org/"},
            {"name": "Intezer", "url": "https://analyze.intezer.com/"}
        ]
    }
