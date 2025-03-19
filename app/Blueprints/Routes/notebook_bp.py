import json
import os
from flask import Blueprint, request, render_template, flash, redirect, url_for, session
from flask_login import login_required, current_user, login_user
from werkzeug.security import generate_password_hash
from Blueprints.models import User, db
from datetime import datetime

# Define the notebook blueprint
notebook_bp = Blueprint('notebook', __name__, url_prefix='/notebook')

# Ensure the notebooks directory exists
NOTEBOOKS_DIR = os.path.join(os.getcwd(), "notebooks")
if not os.path.exists(NOTEBOOKS_DIR):
    os.makedirs(NOTEBOOKS_DIR, exist_ok=True)


# Generate the JSON file path dynamically based on user and date
def get_save_path():
    username = current_user.username
    date_str = datetime.now().strftime('%Y-%m-%d')
    filename = f"{username}-{date_str}.json"
    return os.path.join('notebooks', filename)

# Load notebook data from the user-specific file
def load_notebook():
    save_path = get_save_path()
    if os.path.exists(save_path):
        with open(save_path, 'r') as file:
            return json.load(file)
    else:
        return {
            'notes': [],
            'ips': [],
            'domains': [],
            'services': [],
            'tasks': []
        }

# Save notebook data to the user-specific file
def save_notebook(data):
    save_path = get_save_path()
    os.makedirs(os.path.dirname(save_path), exist_ok=True)  # Ensure directory exists

    with open(save_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=4)



# Import notebook data from a file
@notebook_bp.route('/import', methods=['POST'])
@login_required
def import_notebook():
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('notebook.notebook'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('notebook.notebook'))

    try:
        imported_data = json.load(file)
    except json.JSONDecodeError:
        flash('Invalid JSON file', 'error')
        return redirect(url_for('notebook.notebook'))

    current_notebook = load_notebook()

    # Merge the imported data into the current user's data
    for category, entries in imported_data.items():
        if category in current_notebook:
            for entry in entries:
                # If it's a note, label it with the user who added it
                if category == 'notes':
                    entry['data'] += f" (Imported from {file.filename})"
                current_notebook[category].append(entry)

    save_notebook(current_notebook)
    flash('Notebook data imported successfully!', 'success')
    return redirect(url_for('notebook.notebook'))

# Notebook route
@notebook_bp.route('/', methods=['GET', 'POST'])
@login_required
def notebook():
    # Initialize the notebook session for the user if missing
    if 'notebook' not in session or not isinstance(session['notebook'], dict):
        session['notebook'] = load_notebook()

    if request.method == 'POST':
        category = request.form.get('category')
        entry = request.form.get('entry')
        incident_time = request.form.get('incident_time')

        if not category or not entry or not incident_time:
            flash('All fields are required!', 'error')
            return redirect(url_for('notebook.notebook'))

        try:
            incident_datetime = datetime.strptime(incident_time, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Invalid incident time format!', 'error')
            return redirect(url_for('notebook.notebook'))

        session['notebook'][category].append({
            'data': entry,
            'time': incident_datetime.strftime('%Y-%m-%d %H:%M')
        })
        session.modified = True
        save_notebook(session['notebook'])

        flash('Entry added successfully!', 'success')

    return render_template('notebook.html', notebook=session['notebook'])


# Delete an entry from the notebook
@notebook_bp.route('/delete/<category>/<int:index>', methods=['POST'])
@login_required
def delete_entry(category, index):
    # Ensure the notebook is loaded from the session
    current_notebook = session.get('notebook')

    if not current_notebook or category not in current_notebook:
        flash('Category not found!', 'error')
        return redirect(url_for('notebook.notebook'))

    # Check if the index is valid
    if index < 0 or index >= len(current_notebook[category]):
        flash('Invalid entry index!', 'error')
        return redirect(url_for('notebook.notebook'))

    # Remove the entry
    current_notebook[category].pop(index)

    session.modified = True
    save_notebook(current_notebook)  # Save the updated notebook
    flash('Entry deleted successfully!', 'success')

    return redirect(url_for('notebook.notebook'))



@notebook_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('notebook.notebook'))

        flash('Invalid username or password', 'error')

    return render_template('login.html')


@notebook_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken', 'error')
            return redirect(url_for('notebook.register'))

        # Create new user
        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('notebook.login'))

    return render_template('register.html')
