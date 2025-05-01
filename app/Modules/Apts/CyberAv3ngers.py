def get_content():
    return {
        "id": "G1027",
        "url_id": "CyberAv3ngers",
        "title": "CyberAv3ngers",
        "tags": ["iranian", "state-sponsored", "ICS", "critical-infrastructure", "IRGC-affiliated"],
        "description": "CyberAv3ngers is a suspected Iranian Islamic Revolutionary Guard Corps (IRGC)-affiliated APT group active since at least 2020. The group is best known for its global attacks targeting Unitronics Programmable Logic Controllers (PLCs) with Human-Machine Interfaces (HMI), particularly in critical infrastructure sectors. These attacks included the defacement of device interfaces and disrupted operations across water, energy, manufacturing, and healthcare sectors.",
        "associated_groups": ["Soldiers of Soloman"],
        "campaigns": [
            {
                "id": "C0031",
                "name": "Unitronics Defacement Campaign",
                "first_seen": "November 2023",
                "last_seen": "November 2023",
                "references": [
                    "https://www.cisa.gov/news-events/alerts/2023/12/01/irgc-affiliated-cyber-actors-exploit-plcs-multiple-sectors-including-us-water-and-wastewater-systems-facilities",
                    "https://veronews.com/2023/12/15/hackers-in-iran-attack-computer-at-vero-utilities"
                ]
            }
        ],
        "techniques": [
            "T0812", "T0814", "T0883", "T0826", "T0828", "T0829"
        ],
        "contributors": [],
        "version": "1.0",
        "created": "25 March 2024",
        "last_modified": "10 April 2024",
        "navigator": "",
        "references": [
            {"source": "DHS/CISA", "url": "https://www.cisa.gov/news-events/alerts/2023/12/01/irgc-affiliated-cyber-actors-exploit-plcs-multiple-sectors-including-us-water-and-wastewater-systems-facilities"},
            {"source": "Lisa Zahner", "url": "https://veronews.com/2023/12/15/hackers-in-iran-attack-computer-at-vero-utilities"},
            {"source": "DHS/CISA", "url": "https://www.cisa.gov/news-events/alerts/2023/11/28/exploitation-unitronics-plcs-used-water-and-wastewater-systems"},
            {"source": "Jamie Tarabay and Katrina Manson", "url": "https://www.bloomberg.com/news/articles/2023-12-22/iranian-linked-hacks-expose-failure-to-safeguard-us-water-system"},
            {"source": "Frank Bajak and Marc Levy", "url": "https://apnews.com/article/iran-hackers-water-authority-aliquippa-e3d9a40cb2a6b8e4c675cd27e3ae8f9c"},
            {"source": "WPXI", "url": "https://www.wpxi.com/news/local/officials-investigating-cyberattack-municipal-water-authority-aliquippa/5FL6PZJVGJEN7MYLKAGATIKBNI/"}
        ],
        "resources": ["CISA alerts on Unitronics exploitation", "ICS vulnerability reports"],
        "remediation": "Remove internet exposure of PLC/HMI devices. Change default credentials immediately. Monitor ICS traffic for unauthorized access attempts and defacements.",
        "improvements": "Implement stronger access controls on OT devices, enforce credential hygiene, and segment ICS networks from public-facing infrastructure.",
        "hunt_steps": [
            "Search for unauthorized access to Unitronics PLC HMIs from public IPs.",
            "Audit default or weak credentials in ICS environments.",
            "Detect changes to HMI graphical interfaces or service disruptions.",
            "Monitor for ICS denial-of-service events or device unresponsiveness."
        ],
        "expected_outcomes": [
            "Identification of exposed PLC/HMI devices online.",
            "Detection of default credential use or brute-force attempts.",
            "Evidence of defaced HMI screens or service disruption logs."
        ],
        "false_positive": "Automated scanner traffic might mimic reconnaissance behavior. Validate actions leading to device modification.",
        "clearing_steps": [
            "Reset all passwords on PLC/HMI devices.",
            "Restore original configurations and graphics on HMIs.",
            "Isolate affected devices and perform full integrity checks.",
            "Apply firmware updates and patch exposed vulnerabilities."
        ],
        "ioc": {
            "sha256": [],
            "md5": [],
            "ip": [],
            "domain": [],
            "resources": []
        }
    }
