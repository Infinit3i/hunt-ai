#!/bin/bash

# Build the Docker image
docker build -t hunt-ai .

# Run the container in detached mode
docker run -d -p 31337:31337 hunt-ai

# Wait for the container to start up before opening the browser
sleep 2

# Open the webpage in Google Chrome
google-chrome http://localhost:31337 &
