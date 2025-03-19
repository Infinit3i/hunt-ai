# Standard library imports
import os
import random
import importlib.util
from datetime import datetime

# Third-party imports
from flask import Blueprint, render_template, abort, session, jsonify, request, redirect, flash, url_for

from static.tips import get_random_tip_or_joke

# Local application imports
from static.ascii_text_prompts import full_ascii_art_stripped, infinitei_stripped
from Modules.windows import get_windows_content
from Modules.linux import get_linux_content
from Modules.methodology import get_methodology_content
from Modules.investigate import get_investigate_content

from Modules.Investigate.domain import get_domain_content
from Modules.Investigate.ip import get_ip_content
from Modules.Investigate.malware import get_malware_content
from Modules.Investigate.filehash import get_filehash_content

# Blueprint definition
routes_bp = Blueprint('routes', __name__)

def perform_search(query):
    query = query.lower()
    techniques = load_techniques()  # Load all techniques
    results = []

    for technique in techniques.values():
        for key, value in technique.items():
            if isinstance(value, str) and query in value.lower():
                results.append({
                    "title": technique["title"],
                    "snippet": f"Match found in {key}: {value[:200]}...",
                    "url": url_for("routes.technique_page", url_id=technique["url_id"])
                })
                break  # Stop checking after the first match

            elif isinstance(value, list):  # Handle lists like `hypothesis`, `log_sources`
                for item in value:
                    if isinstance(item, str) and query in item.lower():
                        results.append({
                            "title": technique["title"],
                            "snippet": f"Match found in {key}: {item[:200]}...",
                            "url": url_for("routes.technique_page", url_id=technique["url_id"])
                        })
                        break

                    elif isinstance(item, dict):  # Handle dictionaries like `log_sources`
                        for field_value in item.values():
                            if isinstance(field_value, str) and query in field_value.lower():
                                results.append({
                                    "title": technique["title"],
                                    "snippet": f"Match found in {key}: {field_value[:200]}...",
                                    "url": url_for("routes.technique_page", url_id=technique["url_id"])
                                })
                                break

    return results


@routes_bp.route('/search')
def search():
    query = request.args.get('query')
    results = perform_search(query)  # Your search function
    if not results:
        flash("No results found", "warning")
        # Redirect back to the referring page or a default route if no referrer is available.
        return redirect(request.referrer or url_for('routes.home'))
    return render_template('search_results.html', query=query, results=results)


@routes_bp.route('/')
def home():
    cover_images_path = os.path.join('static', 'Pictures', 'Cover_Images')
    cover_images = [os.path.join('Pictures', 'Cover_Images', filename) 
                    for filename in os.listdir(cover_images_path) 
                    if filename.lower().endswith(('png', 'jpg', 'jpeg', 'gif'))]
    selected_image = random.choice(cover_images) if cover_images else None

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
        selected_image=selected_image,
        random_tip=random_tip,  # Pass the formatted tip only
        random_tip_type=random_tip_type  # Pass the type for styling
    )


# Function to dynamically load tactics from the Tactics folder
def load_tactics():
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


def load_techniques():
    techniques = {}
    techniques_path = os.path.join(os.getcwd(), "Modules", "techniques")

    if not os.path.exists(techniques_path):
        print(f"❌ Folder not found: {techniques_path}")
        return techniques  # Return empty if folder doesn't exist

    for file in os.listdir(techniques_path):
        if file.endswith(".py"):
            file_path = os.path.join(techniques_path, file)
            module_name = file[:-3]  # Remove the .py extension

            print(f"🔍 Loading: {file_path}")  # Debugging output

            # Dynamically import the module
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Check if the module has a `get_content` function
            if hasattr(module, "get_content"):
                technique_data = module.get_content()

                # Ensure valid technique format
                if isinstance(technique_data, dict) and "id" in technique_data and "url_id" in technique_data:
                    # Normalize tactics to lowercase and replace spaces
                    tactic_list = [
                        t.strip().replace(" ", "_").lower()
                        for t in technique_data["tactic"].split(",")
                    ]
                    technique_data["normalized_tactics"] = tactic_list  # Store normalized tactics for filtering
                    techniques[technique_data["url_id"]] = technique_data
                else:
                    print(f"⚠️ Skipping invalid technique file: {file_path}")

    return techniques


@routes_bp.route('/mitre/<tactic>')
def mitre_tactic(tactic):
    # Load all tactics
    mitre_content = load_tactics()

    # Find the selected tactic
    tactic_data = next(
        (item for item in mitre_content if item["title"].replace(" ", "_").lower() == tactic.lower()),
        None
    )
    if not tactic_data:
        abort(404, description="Tactic not found.")

    # Store **only one** tactic in the session (first one listed in techniques)
    session['selected_tactic'] = tactic_data["title"].split(",")[0].strip()

    # Load all techniques and filter only those that contain the tactic
    all_techniques = load_techniques()
    filtered_techniques = {
        key: value
        for key, value in all_techniques.items()
        if tactic.lower() in value["normalized_tactics"]  # Use the normalized tactic list
    }

    print(f"🔍 Found {len(filtered_techniques)} techniques for tactic: {tactic}")  # Debugging output

    return render_template(
        'tactic.html',
        tactic=tactic_data,
        techniques=filtered_techniques,
        current_tactic=tactic_data["title"]
    )


@routes_bp.route('/technique/<path:url_id>')  # Accepts slashes in the URL
def technique_page(url_id):
    # Load all techniques from the /Modules/techniques/ folder
    all_techniques = load_techniques()

    print(f"🔎 Searching for: {url_id}")  # Debugging output

    # Find the technique using url_id
    selected_technique = all_techniques.get(url_id)

    if not selected_technique:
        print(f"❌ Not Found in techniques: {url_id}")  # Debugging output
        print("✅ Loaded Techniques List:")
        for key in all_techniques.keys():
            print(f"   - {key}")  # Show all loaded techniques
        abort(404, description="Technique not found.")

    return render_template('technique.html', technique=selected_technique)


@routes_bp.route('/tactic_techniques/<tactic>')
def tactic_techniques(tactic):
    # Load the tactic's techniques
    tactic_folder = tactic.lower().replace(" ", "_")
    techniques = load_techniques_for_tactic(tactic_folder)
    
    return jsonify(list(techniques.values()))