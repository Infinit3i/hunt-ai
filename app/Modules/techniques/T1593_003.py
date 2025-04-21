def get_content():
    return {
        "id": "T1593.003",
        "url_id": "T1593/003",
        "title": "Search Open Websites/Domains: Code Repositories",
        "description": "Adversaries may search public code repositories (e.g., GitHub, GitLab, BitBucket) for victim-related information. These repositories may expose employee names, project structure, programming languages, third-party services, leaked credentials, API keys, or internal documentation. Adversaries leverage this intelligence to facilitate further reconnaissance, resource development, or initial access.",
        "tags": ["reconnaissance", "osint", "code repository", "github", "gitlab", "leaked credentials"],
        "tactic": "Reconnaissance",
        "protocol": "HTTPS",
        "os": "",
        "tips": [
            "Use GitHub secrets scanning and pre-commit hooks to detect credential leaks before pushing code.",
            "Apply `.gitignore` files correctly to avoid uploading sensitive files.",
            "Monitor public repositories for mentions of your company or sensitive data using GitHub Advanced Search or third-party services."
        ],
        "data_sources": "Application Log, Internet Scan, File",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Internet Scan", "source": "", "destination": ""},
            {"type": "File", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Git History", "location": ".git/logs", "identify": "Commits or revisions containing credentials"},
            {"type": "Command History", "location": "~/.bash_history", "identify": "git clone, curl, grep used to scrape public repos"}
        ],
        "destination_artifacts": [
            {"type": "Public Code Repository", "location": "https://github.com/orgname", "identify": "Exposed API keys, access tokens, or sensitive data"}
        ],
        "detection_methods": [
            "Monitor GitHub, GitLab, and BitBucket for mentions of the organization.",
            "Use token scanning tools to find leaked credentials in public commits.",
            "Set up honeytokens in code to detect unauthorized access when triggered."
        ],
        "apt": ["DEV-0537", "Scattered Spider"],
        "spl_query": [
            'index=github sourcetype=repo_push_events\n| search message="*password*" OR message="*API_KEY*" OR message="*secret*"\n| stats count by repo_name, actor'
        ],
        "hunt_steps": [
            "Search public repositories for your company’s domain, email addresses, or internal terms.",
            "Scan commit histories for potential sensitive data exposures.",
            "Check issues and README.md files for internal notes unintentionally made public."
        ],
        "expected_outcomes": [
            "Detection of exposed credentials or operational details in public code.",
            "Identification of threat actor reconnaissance behavior.",
            "Improved awareness of exposed intellectual property or staff identity."
        ],
        "false_positive": "Public educational or demo repositories may contain placeholder or intentionally exposed keys. Confirm whether the exposed data is valid or production-grade.",
        "clearing_steps": [
            "Revoke any exposed keys or credentials immediately.",
            "Purge sensitive information from commit history using tools like `git filter-branch` or `BFG Repo-Cleaner`.",
            "Enable repository scanning with secret detection tools like GitHub Advanced Security or TruffleHog."
        ],
        "clearing_playbook": [
            "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-leaked-credentials"
        ],
        "mitre_mapping": [
            {"tactic": "Resource Development", "technique": "T1586", "example": "Using exposed credentials to compromise cloud accounts"},
            {"tactic": "Initial Access", "technique": "T1078", "example": "Logging into a system using credentials harvested from public repositories"}
        ],
        "watchlist": [
            "Repositories containing hardcoded secrets",
            "New repos created by employees that are not listed under the org",
            "Mentions of the organization or employees in commit messages or issues"
        ],
        "enhancements": [
            "Set up CI/CD integrations that block commits with sensitive strings.",
            "Implement DLP solutions for development environments.",
            "Educate developers on secure coding practices and OPSEC for code sharing."
        ],
        "summary": "Public code repositories can reveal a wealth of information to adversaries. This includes credentials, internal documentation, infrastructure details, and personal identifiers. Monitoring and hygiene practices are critical to reduce exposure and harden defenses.",
        "remediation": "Regularly audit public repositories for sensitive information, rotate exposed credentials, and apply security-focused git hooks. Implement policies on personal vs. corporate repo usage.",
        "improvements": "Leverage automated tools and threat intelligence to continuously monitor public code spaces. Enforce secure-by-default development practices.",
        "mitre_version": "16.1"
    }
