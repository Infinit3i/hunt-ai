from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from Blueprints.models import db, User

# Define the blueprint
user_creation_bp = Blueprint('user_creation', __name__)

# Route to update theme
@user_creation_bp.route('/set_theme', methods=['POST'])
@login_required
def set_theme():
    data = request.get_json()
    theme = data.get('theme')
    if theme:
        session['theme'] = theme
        flash('Theme updated successfully.', 'success')
    else:
        flash('Invalid theme.', 'error')
    return '', 200


# Registration route
@user_creation_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate input
        if not username or not password or not confirm_password:
            flash('All fields are required.', 'error')
            return redirect(url_for('user_creation.register'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('user_creation.register'))
        
        if len(password) < 10 or not any(char.isupper() for char in password) or \
           not any(char.isdigit() for char in password) or not any(not char.isalnum() for char in password):
            flash('Password does not meet the requirements.', 'error')
            return redirect(url_for('user_creation.register'))
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('user_creation.register'))
        
        # Create a new user
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('user_creation.login'))
    
    return render_template('register.html')

# Login route
@user_creation_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate input
        if not username or not password:
            flash('Both username and password are required.', 'error')
            return render_template('login.html')

        # Fetch user from the database
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid username or password. Please try again.', 'error')
            return render_template('login.html')
        
        # Log the user in
        login_user(user)
        flash('Login successful.', 'success')
        return redirect(url_for('user_creation.profile'))
    
    return render_template('login.html')

# Logout route
@user_creation_bp.route('/logout', methods=['POST'])  # Added methods=['POST']
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('user_creation.login'))


# Profile route
@user_creation_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        role = request.form.get('role')
        theme = request.form.get('theme')
        team = request.form.get('team')
        manager = request.form.get('manager')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')

        if password and password != password_confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('user_creation.profile'))

        # Update user fields
        current_user.role = role
        current_user.theme = theme
        current_user.team = team or None  # Allow empty fields
        current_user.manager = manager or None
        if password:
            current_user.password_hash = generate_password_hash(password)

        db.session.commit()

        # Update the theme in session to reflect changes globally
        session['theme'] = theme

        flash('Profile updated successfully.', 'success')
        return redirect(url_for('user_creation.profile'))

    return render_template(
        'profile.html',
        username=current_user.username,
        role=current_user.role,
        theme=current_user.theme,
        team=current_user.team,
        manager=current_user.manager
    )
