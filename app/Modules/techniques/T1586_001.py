def get_content():
    return {
        "id": "T1586.001",
        "url_id": "1586/001",
        "title": "Compromise Accounts: Social Media Accounts",
        "description": 'Adversaries may compromise social media accounts that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating social media profiles (i.e. "Social Media Accounts"), adversaries may compromise existing social media accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona. A variety of methods exist for compromising social media accounts, such as gathering credentials via "Phishing for Information", purchasing credentials from third-party sites, or by brute forcing credentials (e.g., password reuse from breach credential dumps). Prior to compromising social media accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation. Personas may exist on a single site or across multiple sites (ex: Facebook, LinkedIn, Twitter, etc.). Compromised social media accounts may require additional development, such as modifying profile information, further developing social networks, or incorporating photos. Adversaries can use a compromised social media profile to create new, or hijack existing, connections to targets of interest, potentially leading to Initial Access via "Spearphishing via Service".',
        "tags": [
            "resource-development",
            "social-media-compromise",
            "persona"
        ],
        "tactic": "Resource Development",
        "protocol": "N/A",
        "os": "N/A",
        "tips": [
            "Enable multi-factor authentication (MFA) for all social media accounts, especially those used for business.",
            "Monitor for unexpected or suspicious changes in social media profiles associated with your organization.",
            "Educate employees on risks of connecting with unknown or suspicious profiles claiming affiliation.",
            "Regularly check for leaked credentials or breach data that could compromise social media accounts."
        ],
        "data_sources": "Persona: Social Media, Network Traffic: Network Traffic Content",
        "log_sources": [
            {
                "type": "Persona",
                "source": "Social Media Monitoring",
                "destination": "SIEM"
            },
            {
                "type": "Network Traffic",
                "source": "Inbound/Outbound Traffic Logs",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Credentials",
                "location": "Social media accounts",
                "identify": "Stolen or purchased login information"
            },
            {
                "type": "Persona",
                "location": "Hijacked user identity on social platforms",
                "identify": "Compromised or impersonated social media profile"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Persona",
                "location": "Modified or newly created social media profiles",
                "identify": "Used for social engineering, phishing, or brand impersonation"
            },
            {
                "type": "Connection",
                "location": "Social network connections/friends/followers",
                "identify": "Expanded or hijacked network for malicious targeting"
            }
        ],
        "detection_methods": [
            "Monitor social media for suspicious or newly modified profiles claiming affiliation with your organization",
            "Track large increases in connection requests from certain accounts",
            "Review unusual or uncharacteristic messages/posts from known social media accounts",
            "Correlate known credential leaks or phishing campaigns with suspicious profile changes"
        ],
        "apt": [
            "APT40",
            "Sandworm",
            "NEWSCASTER"
        ],
        "spl_query": [
            "index=social_media_logs (event=\"profile_change\" OR event=\"new_connections\") \n| stats count by profile_id, action \n| where count > 10"
        ],
        "hunt_steps": [
            "Collect social media activity logs for profiles affiliated with your organization.",
            "Search for abnormal spikes in connection/friend requests or unusual content posted.",
            "Correlate known phishing or data breach events with suspicious changes to social media accounts.",
            "Investigate any new or modified profiles claiming to be employees or contractors."
        ],
        "expected_outcomes": [
            "Detection of compromised social media accounts leveraged for social engineering or impersonation.",
            "Identification of suspicious changes in social media profiles associated with targeted organizations.",
            "Early disruption of malicious campaigns that rely on compromised personas for trust-building."
        ],
        "false_positive": "Legitimate profile updates or new hires may appear suspicious if not properly baselined. Verification with the actual user is often necessary.",
        "clearing_steps": [
            "Reset compromised social media account credentials and enable MFA.",
            "Remove unauthorized profile changes, posts, or messages and notify affected contacts.",
            "Suspend or deactivate maliciously altered profiles if platform policy allows.",
            "Coordinate with social media platform support to regain control of compromised accounts."
        ],
        "mitre_mapping": [
            {
                "tactic": "Initial Access",
                "technique": "Spearphishing via Service (T1566.003)",
                "example": "Adversaries may use compromised social media accounts to send phishing messages to contacts."
            }
        ],
        "watchlist": [
            "Social media profiles claiming sudden affiliation with your organization",
            "Unusual or out-of-character messages/posts from established profiles",
            "Excessive connection requests or friend invitations in a short timeframe"
        ],
        "enhancements": [
            "Implement brand protection and social media monitoring services to detect impersonation attempts.",
            "Enable verified badges or official status where possible to distinguish legitimate corporate profiles.",
            "Use threat intelligence feeds to identify known malicious social media accounts or patterns."
        ],
        "summary": "Compromised social media accounts allow adversaries to leverage trusted personas for social engineering, phishing, or impersonation, often bypassing typical reputation checks.",
        "remediation": "Reset compromised social media account credentials, enforce MFA, remove malicious posts, and educate users about suspicious connection requests.",
        "improvements": "Adopt robust social media monitoring, integrate threat intelligence for known malicious profiles, and regularly validate employee accounts for unauthorized changes."
    }
