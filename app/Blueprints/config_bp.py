# Standard library imports
import argparse
from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash

# Import the version from Config/config.py
from Config.config import VERSION

# Blueprint definition
config_bp = Blueprint('config', __name__, url_prefix='/config')


def handle_arguments():
    parser = argparse.ArgumentParser(
        description="Hunt-AI Application Command-Line Interface",
        usage="python3 app.py [-v | --custom-help]"
    )
    parser.add_argument("-v", "--version", action="store_true", help="Display the application version")
    parser.add_argument("--custom-help", action="store_true", help="Show custom help information")
    args = parser.parse_args()

    if args.version:
        print(f"Hunt-AI Version: {VERSION}")
        exit(0)

    if args.custom_help:
        print(parser.format_help())
        exit(0)
