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

def make_env_persistent(activate_script):
    """Add the virtual environment activation to the shell's startup file."""
    shell = os.environ.get("SHELL", "")
    if "bash" in shell:
        rc_file = os.path.expanduser("~/.bashrc")
    elif "zsh" in shell:
        rc_file = os.path.expanduser("~/.zshrc")
    else:
        print("Unsupported shell for automatic persistence. Please manually add the activation command. ❌")
        return

    activation_line = f"source {os.path.abspath(activate_script)}\n"
    
    # Check if activation is already added
    try:
        with open(rc_file, "r") as file:
            if activation_line.strip() in file.read():
                print(f"Virtual environment activation is already persistent in {rc_file}. ✅")
                return
    except FileNotFoundError:
        pass  # If the file doesn't exist, it will be created later

    # Append the activation command to the shell configuration file
    with open(rc_file, "a") as file:
        file.write(f"\n# Activate hunt-ai virtual environment automatically\n{activation_line}")
    print(f"Virtual environment activation added to {rc_file}. ✅")
    print(f"Restart your terminal or run 'source {rc_file}' for changes to take effect. 🌟")

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

    # Make the virtual environment persistent
    make_env_persistent(activate_script)

    print("Requirements installed successfully! ✅")
    print("Setup completed. You can now use the virtual environment! 🎉")

if __name__ == "__main__":
    main()
