import os
from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from Blueprints.models import db, User
from Blueprints.user_creation_bp import user_creation_bp
from Blueprints.routes import routes_bp
from Blueprints.Routes.notebook_bp import notebook_bp


from static.tips import *
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import sys

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Register blueprints
app.register_blueprint(user_creation_bp)
app.register_blueprint(routes_bp)
app.register_blueprint(notebook_bp, url_prefix='/notebook')

# SQLAlchemy configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the db object with the app
db.init_app(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user_creation.login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# Context processor to inject theme
@app.context_processor
def inject_theme():
    # Retrieve theme from session or default to 'modern' if not set
    theme = session.get('theme', current_user.theme if current_user.is_authenticated else 'modern')
    return {'theme': theme}

@app.context_processor
def inject_random_tip():
    random_tip, random_tip_type = get_random_tip_or_joke()
    return {
        'random_tip': random_tip,
        'random_tip_type': random_tip_type
    }


# Ensure database tables are created
with app.app_context():
    db.create_all()
    print("Database tables created successfully.")

# Watchdog event handler class
class FlaskReloadHandler(FileSystemEventHandler):
    def __init__(self, app):
        self.app = app

    def on_modified(self, event):
        # Trigger reload when Python files, templates, or static files change
        if event.src_path.endswith('.py') or event.src_path.endswith('.html') or event.src_path.endswith('.css'):
            print(f"Detected change in {event.src_path}. Reloading Flask app...")
            # Shutdown the app and restart it by running it on a separate thread
            self.app.do_teardown_appcontext()
            sys.exit()  # Terminate the process to trigger auto-restart by flask run

# Set up watchdog observer
def start_watchdog():
    observer = Observer()
    observer.schedule(FlaskReloadHandler(app), path='.', recursive=True)  # Watch the entire project directory
    observer.start()
    try:
        while True:
            time.sleep(1)  # Keeps the process alive
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == '__main__':
    # Start watchdog in a separate thread or process for file watching
    from threading import Thread
    watcher_thread = Thread(target=start_watchdog, daemon=True)
    watcher_thread.start()

    # Start Flask app
    app.run(debug=True, port=31337)
