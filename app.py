import argparse
import sys
import os
import re
import random

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy

from werkzeug.security import generate_password_hash, check_password_hash

from Modules.windows import get_windows_content
from Modules.rule_creation import get_rule_creation_content
from Modules.linux import get_linux_content
from Modules.tips import get_random_tip_or_joke
from Modules.methodology import get_methodology_content
from Modules.investigate import get_investigate_content

from Modules.Investigate.threat import *
from Modules.Investigate.ip import *
from Modules.Investigate.domain import *
from Modules.Investigate.filehash import *
from Modules.Investigate.malware import *

from static.ascii_text_prompts import full_ascii_art_stripped, infinitei_stripped
from Config.config import VERSION

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize login manager for session handling
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login if user is not authenticated

# SQLAlchemy configuration (Replace this with your database URI)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Example for SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking

# Initialize the db object
db = SQLAlchemy(app)

# In-memory database simulation
users_db = {}

# User class for SQLAlchemy (you can replace your in-memory dictionary)
class User(db.Model, UserMixin):
    id = db.Column(db.String(80), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Unknown')
    theme = db.Column(db.String(50), nullable=False, default='dark')
    team = db.Column(db.String(50), nullable=True, default='Unknown')
    manager = db.Column(db.String(50), nullable=True, default='Unknown')

    def __repr__(self):
        return f"<User {self.username}>"

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    # Ensure that user_id corresponds to the username or unique user identifier
    user = users_db.get(user_id)
    if user:
        # Return a User instance, not a dictionary
        return User(id=user_id, 
                    username=user["username"], 
                    email=user["email"],
                    password_hash=user["password_hash"],
                    role=user["role"],
                    theme=user.get("theme", "modern"),
                    team=user.get("team", "Unknown"),
                    manager=user.get("manager", "Unknown"))
    return None  # Return None if user not found

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_role = request.form.get('role')
        app.logger.debug(f'New role selected: {new_role}')  # Log the new role
        
        role = request.form['role']  # Capture the role from the form
        theme = request.form['theme']
        team = request.form['team']
        manager = request.form['manager']
        new_password = request.form['password']
        password_confirm = request.form['password_confirm']

        # Validate the role
        if not role:
            flash('Please select a valid role.', 'error')
            return redirect(url_for('profile'))

        # Validate team and manager fields
        if not team or not manager:
            flash('Team and Manager fields are required.', 'error')
            return redirect(url_for('profile'))

        # Update the password if provided
        if new_password:
            if new_password != password_confirm:
                flash('The passwords do not match.', 'error')
                return redirect(url_for('profile'))
            current_user.password_hash = generate_password_hash(new_password)

        # Update the current_user fields (role, theme, team, manager)
        current_user.role = role
        current_user.theme = theme
        current_user.team = team
        current_user.manager = manager

        # Commit changes to the database
        db.session.commit()
        flash('Profile updated successfully.')

        # Update the theme in the session to reflect immediately
        session['theme'] = current_user.theme
        session['role'] = current_user.role  # Save the role to the session

        return render_template('profile.html', 
                              username=current_user.username, 
                              email=current_user.email, 
                              role=current_user.role, 
                              theme=session.get('theme', 'dark'), 
                              team=current_user.team, 
                              manager=current_user.manager)

    # Get the current theme from the session or default to 'dark'
    theme = session.get('theme', current_user.theme if current_user.is_authenticated else 'dark')

    return render_template('profile.html', 
                           username=current_user.username, 
                           email=current_user.email, 
                           role=current_user.role, 
                           theme=theme, 
                           team=current_user.team, 
                           manager=current_user.manager)

@app.route('/set_theme', methods=['POST'])
def set_theme():
    theme = request.json.get('theme', 'modern')  # Default to 'modern'
    if theme not in ['modern', 'dark', 'light']:
        return {"error": "Invalid theme"}, 400

    if current_user.is_authenticated:
        current_user.theme = theme
        db.session.commit()
    session['theme'] = theme  # Update session theme for guests
    return {"message": "Theme updated successfully"}, 200


































# In-memory data store for the notebook page
notebook = {
    "notes": [],
    "ips": [],
    "domains": [],
    "services": [],
    "tasks": []
}

@app.context_processor
def inject_theme():
    # Default to 'modern' if no theme is set in the session or user
    theme = session.get('theme', current_user.theme if current_user.is_authenticated else 'modern')
    return dict(theme=theme)

@app.context_processor
def inject_tip():
    """
    Add a random tip or joke to every page's context.
    """
    return {"random_tip": get_random_tip_or_joke()}

README_PATH = os.path.join(os.getcwd(), "README.md")


def get_readme_description():
    """
    Extract the description starting with "HUNT-AI" and stopping at the next blank line from the README.md file.
    """
    if not os.path.exists(README_PATH):
        return "No description available."

    description = []
    capture = False

    try:
        with open(README_PATH, "r", encoding="utf-8") as readme_file:
            for line in readme_file:
                # Start capturing from the line containing "HUNT-AI"
                if "HUNT-AI" in line:
                    capture = True
                    description.append(line.strip())
                # Continue capturing until a blank line is encountered
                elif capture:
                    if line.strip() == "":
                        break
                    description.append(line.strip())
    except Exception as e:
        return f"Error reading README.md: {e}"

    return " ".join(description) if description else "No description available."

# Home route
@app.route('/')
def home():
    cover_images_path = os.path.join(app.static_folder, 'Pictures', 'Cover_Images')
    cover_images = [os.path.join('Pictures', 'Cover_Images', filename) for filename in os.listdir(cover_images_path) if filename.lower().endswith(('png', 'jpg', 'jpeg', 'gif'))]
    selected_image = random.choice(cover_images) if cover_images else None
    readme_description = get_readme_description()

    links = [
        {"name": "Visit Start.me", "url": "https://start.me/p/qbzw4e/cyber-security"},
        {"name": "Visit My Website", "url": "https://infinit3i.com/"}
    ]
    return render_template(
        'index.html',
        full_ascii_art=full_ascii_art_stripped,
        infinitei=infinitei_stripped,
        links=links,
        readme_description=readme_description,
        selected_image=selected_image
    )

@app.route('/methodology')
def methodology():
    content = get_methodology_content()
    return render_template('methodology.html', content=content)

@app.route('/methodology/<title>')
def methodology_section(title):
    content = get_methodology_content()
    section = next((s for s in content if s["title"].replace(" ", "_").lower() == title.lower()), None)
    if not section:
        abort(404)
    return render_template('section.html', section=section)

@app.route('/linux')
def linux():
    sections = get_linux_content()
    return render_template('linux.html', sections=sections)

@app.route('/linux/<title>')
def linux_section(title):
    sections = get_linux_content()
    section = next((s for s in sections if s["title"].replace(" ", "_").lower() == title.lower()), None)
    if not section:
        abort(404)
    return render_template('section.html', section=section)

@app.route('/rule_creation')
def rule_creation():
    content = get_rule_creation_content()
    return render_template('rule_creation.html', content=content)

@app.route('/windows')
def windows():
    # Load all sections
    sections = get_windows_content()
    return render_template('windows.html', sections=sections)

@app.route('/windows/<title>')
def windows_section(title):
    # Find the section matching the title
    sections = get_windows_content()
    section = next((s for s in sections if s["title"].replace(" ", "_").lower() == title.lower()), None)

    if not section:
        abort(404)  # Return a 404 if the section is not found

    return render_template('section.html', section=section)









@app.route('/persistence')
def persistence_submenu():
    """
    Displays the submenu for all persistence methods.
    """
    menu = get_persistence_menu()
    return render_template('persistence_submenu.html', menu=menu)

@app.route('/persistence/<method>')
def persistence_method(method):
    """
    Dynamically load content for a specific persistence method.
    """
    try:
        # Dynamically import the requested method module
        module = __import__(f"Modules.Persistence.{method}", fromlist=["get_content"])
        content = module.get_content()
        return render_template('persistence_method.html', content=content)
    except ModuleNotFoundError:
        abort(404, description=f"Persistence method '{method}' not found.")

























@app.route('/investigate')
def investigate():
    content = get_investigate_content()
    return render_template('investigate.html', content=content)

@app.route('/investigate/threat')
def investigate_threat():
    content = get_threat_content()
    return render_template('investigate.html', content=content)

@app.route('/investigate/domain')
def investigate_domain():
    content = get_domain_content()
    return render_template('investigate.html', content=content)

@app.route('/investigate/filehash')
def investigate_filehash():
    content = get_filehash_content()
    return render_template('investigate.html', content=content)

@app.route('/investigate/ip')
def investigate_ip():
    content = get_ip_content()
    return render_template('investigate.html', content=content)

@app.route('/investigate/malware')
def investigate_malware():
    content = get_malware_content()
    return render_template('investigate.html', content=content)

def display_help():
    """
    Display help information for the command-line interface.
    """
    help_text = f"""
Usage:
    python3 app.py          Start the Flask application
    python3 app.py -v       Display the current version
    python3 app.py -h       Show this help page
    python3 app.py -f <file> Load the last session file for collaboration
    """
    print(help_text)

def get_version():
    """
    Display the version of the application.
    """
    print(f"App Version: {VERSION}")

def load_session(file_path):
    """
    Load a session file and display its contents.
    """
    try:
        with open(file_path, "r") as file:
            session_data = file.read()
        print(f"Session loaded successfully from {file_path}:\n")
        print(session_data)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"Error: {e}")

def handle_arguments():
    """
    Parse and handle command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="App Runner - Threat AI Command Interface",
        usage="python3 app.py [-v | -h | -f <file>]"
    )
    parser.add_argument("-v", "--version", action="store_true", help="Display the current version")
    parser.add_argument("-f", "--file", type=str, help="Load the last session file for collaboration")
    args = parser.parse_args()

    if args.version:
        get_version()
        sys.exit(0)
    elif args.file:
        load_session(args.file)
        sys.exit(0)



# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Password validation
        password_pattern = re.compile(r'^(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{10,}$')
        if not password_pattern.match(password):
            flash("Password must be at least 10 characters, contain 1 uppercase letter, 1 special character, and 1 number.", "error")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('register'))

        # Hash the password
        password_hash = generate_password_hash(password)

        # Create user and store in the in-memory database
        user = {
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'role': 'Lead Analyst',  # Default role
            'theme': 'dark',        # Default theme
            'team': 'Unknown',       # Default team
            'manager': 'Unknown'     # Default manager
        }

        users_db[username] = user

        # Log the user in after registration
        user_obj = User(
            id=username,
            username=username,
            email=email,
            password_hash=password_hash,
            role=user['role'],
            theme=user['theme'],
            team=user['team'],
            manager=user['manager']
        )
        login_user(user_obj)

        flash("Account created and logged in successfully!", "success")
        return redirect(url_for('home'))  # Redirect to home or another page after successful login

    return render_template('register.html')







# User Login Route (optional if you want a login page)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Get the user dictionary from users_db
        user = users_db.get(username)

        if user and check_password_hash(user["password_hash"], password):
            # Create a User instance, not just a dictionary
            user_obj = User(id=username,  # Assign user ID (username)
                            username=user["username"], 
                            email=user["email"],
                            password_hash=user["password_hash"],
                            role=user["role"],
                            theme=user.get("theme", "light"),  # Default to 'light' if not found
                            team=user.get("team", "Unknown"),  # Default to 'Unknown' if not found
                            manager=user.get("manager", "Unknown"))  # Default to 'Unknown' if not found

            # Log the user in
            login_user(user_obj)
            return redirect(url_for('notebook_page'))  # Redirect to notebook page after login
        else:
            flash('Invalid username or password.')
            return redirect(url_for('login'))

    return render_template('login.html')



# Notebook route (Protected)
@app.route('/notebook', methods=['GET', 'POST'])
@login_required
def notebook_page():
    if request.method == 'POST':
        category = request.form.get('category')
        entry = request.form.get('entry', '').strip()  # Strip whitespace from the entry

        if not category or not entry:
            flash("Category and entry cannot be empty.", "error")
            return redirect(url_for('notebook_page'))

        if category not in notebook:
            flash("Invalid category selected.", "error")
            return redirect(url_for('notebook_page'))

        # Input validation
        if category == "ips":
            # Ensure valid IP address
            ip_pattern = re.compile(
                r'^((25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'
            )
            if not ip_pattern.match(entry):
                flash("Invalid IP address format.", "error")
                return redirect(url_for('notebook_page'))
        elif category == "notes":
            # Ensure notes are over 1 character
            if len(entry) < 2:
                flash("Notes must be at least 2 characters long.", "error")
                return redirect(url_for('notebook_page'))

        # Add valid entry to the notebook
        notebook[category].append(entry)
        flash(f"Entry added to {category.capitalize()}!", "success")
        return redirect(url_for('notebook_page'))

    return render_template('notebook.html', notebook=notebook)


# Delete an entry from notebook
@app.route('/delete/<category>/<int:index>')
@login_required
def delete_entry(category, index):
    if category in notebook and 0 <= index < len(notebook[category]):
        deleted_entry = notebook[category].pop(index)
        flash(f"Deleted entry: {deleted_entry} from {category.capitalize()}.", "info")
    else:
        flash("Invalid entry or category.", "error")
    return redirect(url_for('notebook_page'))

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))


















def aggregate_content():
    """
    Aggregates content from all module files under the Modules directory.
    Returns a list of dictionaries with 'title' and 'content'.
    """
    content_list = []
    modules_dir = "Modules"

    for root, _, files in os.walk(modules_dir):
        for file in files:
            if file.endswith(".py") and not file.startswith("__"):
                module_path = os.path.join(root, file).replace("/", ".").replace("\\", ".")[:-3]
                try:
                    module = importlib.import_module(module_path)
                    if hasattr(module, "get_content"):
                        content_list.extend(module.get_content())
                except Exception as e:
                    print(f"Error importing {module_path}: {e}")
    
    return content_list



def perform_search(query):
    """
    Searches the aggregated content for matching titles or content.
    """
    all_content = aggregate_content()
    query = query.lower()
    results = [
        {
            "title": item["title"],
            "snippet": item["content"][:150] + "...",  # Return the first 150 characters as a snippet
            "module": item.get("module", "Unknown")  # Optional: Include module info
        }
        for item in all_content
        if query in item["title"].lower() or query in item["content"].lower()
    ]
    return results

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip()
    if not query:
        flash("Search query cannot be empty.", "error")
        return redirect(url_for('home'))

    # Perform search
    results = perform_search(query)

    # Render results
    return render_template('search_results.html', query=query, results=results)





























if __name__ == '__main__':
    # If arguments are passed, handle them; otherwise, run the Flask app.
    if len(sys.argv) > 1:
        handle_arguments()
    else:
        app.run(debug=True, port=31337)