import subprocess


def main():
    # Number of Gunicorn workers
    workers = 4
    
    # Bind address and port
    bind_address = "0.0.0.0:31337"
    
    # Application entry point (format: module_name:app_name)
    app_entry = "app:app"
    
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