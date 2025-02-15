def get_ip_content():
    """
    Returns content for the IP Analysis page.
    """
    return {
        "title": "IP Analysis",
        "description": "Explore tools and resources for analyzing IP addresses.",
        "resources": [
            {"name": "VirusTotal", "url": "https://www.virustotal.com/gui/"},
            {"name": "Scam Adviser", "url": "https://www.scamadviser.com/"},
            {"name": "Censys", "url": "https://search.censys.io/"},
            {"name": "Shodan", "url": "https://www.shodan.io/"},
            {"name": "Feodo Tracker", "url": "https://feodotracker.abuse.ch/browse/"},
            {"name": "IBM X-Force", "url": "https://exchange.xforce.ibmcloud.com/"},
            {"name": "GreyNoise", "url": "https://viz.greynoise.io/"}
        ]
    }
