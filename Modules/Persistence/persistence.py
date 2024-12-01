from flask import url_for

def get_persistence_menu():
    """
    Returns the submenu for persistence methods.
    Each method will link to its corresponding content page.
    """
    return {
        "title": "Persistence Methods",
        "description": "Explore various persistence methods used by adversaries to maintain access.",
        "methods": [
            {"name": "Autostart", "url": url_for("persistence_method", method="autostart")},
            {"name": "Basic Persistence", "url": url_for("persistence_method", method="basic_persistence")},
            {"name": "DCOM", "url": url_for("persistence_method", method="dcom")},
            {"name": "DLL Hijacking", "url": url_for("persistence_method", method="dll_hijacking")},
            {"name": "Map Share", "url": url_for("persistence_method", method="map_share")},
            {"name": "PowerShell Remoting", "url": url_for("persistence_method", method="powershell_remoting")},
            {"name": "PsExec", "url": url_for("persistence_method", method="psexec")},
            {"name": "RDP", "url": url_for("persistence_method", method="rdp")},
            {"name": "Scheduled Tasks", "url": url_for("persistence_method", method="scheduled_tasks")},
            {"name": "Services", "url": url_for("persistence_method", method="services")},
            {"name": "SMBExec", "url": url_for("persistence_method", method="smbexec")},
            {"name": "WMI", "url": url_for("persistence_method", method="wmi")},
            {"name": "Advanced", "url": url_for("persistence_method", method="advanced")}
        ]
    }
