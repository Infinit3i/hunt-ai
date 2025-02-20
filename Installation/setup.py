import os
import sys
import subprocess

def run_command(command, error_message):
    """Run a shell command and handle errors."""
    try:
        subprocess.check_call(command, shell=True, executable="/bin/bash")
    except subprocess.CalledProcessError:
        print(f"{error_message} ❌")
        sys.exit(1)

def main():
    # Check if Python3 is available
    if not sys.version_info >= (3, 0):
        print("Python3 is not installed. Please install Python3 to continue. ❌")
        sys.exit(1)
    print("✅ Python3 found.")

    # Create a virtual environment
    print("Creating virtual environment... 🛠️")
    run_command("python3 -m venv hunt-ai", "Failed to create virtual environment.")

    # Activate the virtual environment
    print("Activating virtual environment... 🌟")
    activate_script = "hunt-ai/bin/activate" if os.name != "nt" else "hunt-ai\\Scripts\\activate"
    if not os.path.exists(activate_script):
        print("Failed to activate virtual environment. ❌")
        sys.exit(1)
    print("Virtual environment activated. ✅")

    # Install requirements
    print("Installing requirements... 📦")
    if os.name == "nt":
        pip_install_command = f"{activate_script} && pip install -r requirements.txt"
    else:
        pip_install_command = f"bash -c 'source {activate_script} && pip install -r requirements.txt'"
    
    run_command(pip_install_command, "Failed to install requirements.")

    print("Requirements installed successfully! ✅")
    print("Setup completed. You can now use the virtual environment! 🎉")

if __name__ == "__main__":
    main()
