import subprocess
import sys
import os

# Fix import path issues
sys.path.append("/app")

def main():
    # Number of Gunicorn workers
    workers = 4
    
    # Bind address and port
    bind_address = "0.0.0.0:31337"
    
    # Application entry point (adjusted to app.app)
    app_entry = "app.app:app"

    # Command to run Gunicorn
    command = f"gunicorn -w {workers} -b {bind_address} {app_entry}"
    
    try:
        print("Starting Gunicorn server... 🚀")
        subprocess.check_call(command, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to start Gunicorn server. Error: {e}")
    except KeyboardInterrupt:
        print("\nServer stopped by user. 👋")

if __name__ == "__main__":
    main()
