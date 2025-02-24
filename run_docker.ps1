# Build the Docker image
docker build -t hunt-ai .

# Run the Docker container in detached mode, mapping the required port
docker run -d -p 31337:31337 hunt-ai

# Wait for the container to start up before opening the browser
Start-Sleep -Seconds 2

# Open the webpage in the default web browser (Google Chrome in this example)
Start-Process "chrome.exe" "http://localhost:31337"



# Might have to run this command to allow the script to run
# Set-ExecutionPolicy RemoteSigned -Scope CurrentUser