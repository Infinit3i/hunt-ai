import os
import json
import re
import socket
from datetime import datetime
from flask import Blueprint, request, render_template, redirect, url_for, flash, session
from flask_login import login_required, current_user

# Define the notebook blueprint
notebook_bp = Blueprint('notebook', __name__, url_prefix='/notebook')

# Generate the JSON file path dynamically based on user and date
def get_save_path():
    username = current_user.username
    date_str = datetime.now().strftime('%Y-%m-%d')
    filename = f"{username}-{date_str}.json"
    return os.path.join('notebooks', filename)

# Ensure the notebooks directory exists
if not os.path.exists('notebooks'):
    os.makedirs('notebooks')

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
    with open(save_path, 'w') as file:
        json.dump(data, file, indent=4)

# Notebook route
@notebook_bp.route('/', methods=['GET', 'POST'])
@login_required
def notebook():
    if 'notebook' not in session:
        session['notebook'] = load_notebook()

    if request.method == 'POST':
        category = request.form.get('category')
        entry = request.form.get('entry')
        incident_time = request.form.get('incident_time')

        if not category or not entry or not incident_time:
            flash('All fields are required!', 'error')
            return redirect(url_for('notebook.notebook'))

        try:
            # Validate time format
            incident_datetime = datetime.strptime(incident_time, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Invalid incident time format!', 'error')
            return redirect(url_for('notebook.notebook'))

        if category == 'ips':
            # Validate IP address
            ip_pattern = re.compile(
                r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
            )  # Simple IPv4 regex
            if not ip_pattern.match(entry):
                flash('Invalid IP address format!', 'error')
                return redirect(url_for('notebook.notebook'))

            try:
                # Lookup hostname
                hostname = socket.gethostbyaddr(entry)[0]
            except socket.herror:
                hostname = 'Unknown'

            session['notebook']['ips'].append({
                'data': entry,
                'time': incident_datetime.strftime('%Y-%m-%d %H:%M'),
                'hostname': hostname
            })
        else:
            session['notebook'][category].append({
                'data': entry,
                'time': incident_datetime.strftime('%Y-%m-%d %H:%M')
            })

        session.modified = True
        save_notebook(session['notebook'])
        flash('Entry added successfully!', 'success')

    return render_template('notebook.html', notebook=session['notebook'])

# Delete entry route
@notebook_bp.route('/delete/<category>/<int:index>', methods=['POST', 'GET'])
@login_required
def delete_entry(category, index):
    if category in session['notebook']:
        try:
            session['notebook'][category].pop(index)
            session.modified = True
            save_notebook(session['notebook'])
            flash('Entry deleted successfully!', 'success')
        except IndexError:
            flash('Invalid entry index!', 'error')
    else:
        flash('Invalid category!', 'error')

    return redirect(url_for('notebook.notebook'))
