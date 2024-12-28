# Standard library imports
import os
import random
import socket
import importlib.util
from datetime import datetime
import re

# Third-party imports
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session
from flask_login import login_required, current_user

from static.tips import get_random_tip_or_joke

# Local application imports
from static.ascii_text_prompts import full_ascii_art_stripped, infinitei_stripped
from Modules.windows import get_windows_content
from Modules.linux import get_linux_content
from Modules.methodology import get_methodology_content
from Modules.investigate import get_investigate_content
from Modules.Persistence.persistence import get_persistence_menu

from Modules.Investigate.threat import get_threat_content
from Modules.Investigate.domain import get_domain_content
from Modules.Investigate.ip import get_ip_content
from Modules.Investigate.malware import get_malware_content
from Modules.Investigate.filehash import get_filehash_content

# Blueprint definition
routes_bp = Blueprint('routes', __name__)



# Helper functions
def get_readme_description():
    """Extracts and returns the project description from README.md."""
    README_PATH = os.path.join(os.getcwd(), "README.md")
    if not os.path.exists(README_PATH):
        return "No description available."

    description = []
    capture = False

    try:
        with open(README_PATH, "r", encoding="utf-8") as readme_file:
            for line in readme_file:
                if "HUNT-AI" in line:
                    capture = True
                    description.append(line.strip())
                elif capture and not line.strip():
                    break
                elif capture:
                    description.append(line.strip())
    except Exception as e:
        return f"Error reading README.md: {e}"

    return " ".join(description) if description else "No description available."


@routes_bp.route('/')
def home():
    cover_images_path = os.path.join('static', 'Pictures', 'Cover_Images')
    cover_images = [os.path.join('Pictures', 'Cover_Images', filename) 
                    for filename in os.listdir(cover_images_path) 
                    if filename.lower().endswith(('png', 'jpg', 'jpeg', 'gif'))]
    selected_image = random.choice(cover_images) if cover_images else None
    readme_description = get_readme_description()

    links = [
        {"name": "Visit Start.me", "url": "https://start.me/p/qbzw4e/cyber-security"},
        {"name": "Visit My Website", "url": "https://infinit3i.com/"}
    ]

    # Generate a random tip, joke, or T-code
    random_tip, random_tip_type = get_random_tip_or_joke(clean=False)

    # Ensure theme is set in the session
    if 'theme' not in session:
        session['theme'] = 'modern'

    return render_template(
        'index.html',
        full_ascii_art=full_ascii_art_stripped,
        infinitei=infinitei_stripped,
        links=links,
        readme_description=readme_description,
        selected_image=selected_image,
        random_tip=random_tip,  # Pass the formatted tip only
        random_tip_type=random_tip_type  # Pass the type for styling
    )


# Function to dynamically load tactics from the Tactics folder
def load_tactics():
    """
    Dynamically loads tactics from the Tactics folder and sorts them by tactic_id.
    """
    tactics_path = os.path.join(os.getcwd(), 'Modules', 'Tactics')
    tactics = []

    # Iterate through all Python files in the Tactics folder
    for file in os.listdir(tactics_path):
        if file.endswith('.py'):
            file_path = os.path.join(tactics_path, file)
            module_name = file[:-3]  # Remove the .py extension

            # Dynamically import the module
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Check if the module has a `get_content` function
            if hasattr(module, 'get_content'):
                tactics.extend(module.get_content())

    # Sort tactics by their tactic_id (e.g., TA0001, TA0002)
    tactics.sort(key=lambda x: x.get("tactic_id", ""))
    return tactics


# Update the '/mitre' route
@routes_bp.route('/mitre')
def mitre():
    # Dynamically load tactics from the Tactics folder
    mitre_content = load_tactics()  # This function loads all tactic data dynamically
    return render_template('mitre.html', mitre_content=mitre_content)

# Define a dynamic route for individual tactics
@routes_bp.route('/mitre/<tactic>')
def mitre_tactic(tactic):
    # Dynamically load tactics
    mitre_content = load_tactics()

    # Find the specific tactic using the tactic's title
    tactic_data = next(
        (item for item in mitre_content if item["title"].replace(" ", "_").lower() == tactic.lower()),
        None
    )
    if not tactic_data:
        abort(404, description="Tactic not found.")

    # Render the tactic-specific page and pass the content
    return render_template('tactic.html', tactic=tactic_data)


# Methodology routes
@routes_bp.route('/methodology')
def methodology():
    content = get_methodology_content()
    return render_template('methodology.html', content=content)

@routes_bp.route('/methodology/<title>')
def methodology_section(title):
    content = get_methodology_content()
    section = next((s for s in content if s["title"].replace(" ", "_").lower() == title.lower()), None)
    if not section:
        abort(404)
    return render_template('section.html', section=section)


# Linux routes
@routes_bp.route('/linux')
def linux():
    sections = get_linux_content()
    return render_template('linux.html', sections=sections)

@routes_bp.route('/linux/<title>')
def linux_section(title):
    sections = get_linux_content()
    section = next((s for s in sections if s["title"].replace(" ", "_").lower() == title.lower()), None)
    if not section:
        abort(404)
    return render_template('section.html', section=section)


# Windows routes
@routes_bp.route('/windows')
def windows():
    sections = get_windows_content()
    return render_template('windows.html', sections=sections)

@routes_bp.route('/windows/<title>')
def windows_section(title):
    sections = get_windows_content()
    section = next((s for s in sections if s["title"].replace(" ", "_").lower() == title.lower()), None)
    if not section:
        abort(404)
    return render_template('section.html', section=section)


# Investigate routes
@routes_bp.route('/investigate')
def investigate():
    content = get_investigate_content()
    return render_template('investigate.html', content=content)

@routes_bp.route('/investigate/threat')
def investigate_threat():
    content = get_threat_content()
    return render_template('investigate.html', content=content)

@routes_bp.route('/investigate/domain')
def investigate_domain():
    content = get_domain_content()
    return render_template('investigate.html', content=content)

@routes_bp.route('/investigate/filehash')
def investigate_filehash():
    content = get_filehash_content()
    return render_template('investigate.html', content=content)

@routes_bp.route('/investigate/ip')
def investigate_ip():
    content = get_ip_content()
    return render_template('investigate.html', content=content)

@routes_bp.route('/investigate/malware')
def investigate_malware():
    content = get_malware_content()
    return render_template('investigate.html', content=content)


# Persistence routes
@routes_bp.route('/persistence')
def persistence_submenu():
    menu = get_persistence_menu()
    return render_template('persistence_submenu.html', menu=menu)

@routes_bp.route('/persistence/<method>')
def persistence_method(method):
    try:
        module = __import__(f"Modules.Persistence.{method}", fromlist=["get_content"])
        content = module.get_content()
        return render_template('persistence_method.html', content=content)
    except ModuleNotFoundError:
        abort(404, description=f"Persistence method '{method}' not found.")
        
        

