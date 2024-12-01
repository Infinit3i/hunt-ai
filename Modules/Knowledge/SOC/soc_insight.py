def get_content():
    """
    Returns structured content from keynote speakers and their insights.
    """
    return [
        {
            "title": "Allie Mellen's Insights",
            "content": """
- Works at Forester, MIT, Fortune 500 CISO, and as a principal analyst.
- Focus areas:
    - Security operations, detection and response engineering.
    - Research on nation-state threats.
- Key Thoughts:
    - Autonomous SOCs are unrealistic; manual work is inevitable.
    - SOC analysts must develop creative solutions to adapt.
            """
        },
        {
            "title": "Eli Short's Insights",
            "content": """
- Issues in Rule Management:
    - Most rules are outdated or unused after a few years.
    - Organizations fail to track and optimize rule usage.
- Recommendations:
    - Adopt threat-informed defense strategies.
    - Ensure realistic expectations based on available logs and data.
            """
        }
    ]
