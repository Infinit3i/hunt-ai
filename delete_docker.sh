#!/bin/bash

# Remove all stopped containers
echo "Removing all stopped containers..."
docker rm $(docker ps -aq)

# Remove all Docker networks (if needed)
echo "Removing all unused Docker networks..."
docker network prune -f

# Remove all Docker volumes (⚠ Be careful, this deletes persistent data)
echo "Removing all unused Docker volumes..."
docker volume prune -f

# Remove all Docker images (⚠ Be careful, this will remove all images)
echo "Removing all Docker images..."
docker rmi -f $(docker images -q)

# (Optional) Clean up everything in Docker (containers, images, networks, and volumes)
echo "Performing full system prune (containers, images, networks, volumes)..."
docker system prune -af --volumes

# Verify Docker is clean
echo "Verifying Docker cleanup..."

# Verify containers are removed
echo "Containers:"
docker ps -a   # Should return nothing if all containers are removed

# Verify images are removed
echo "Images:"
docker images  # Should return nothing if all images are removed

# Optional: List networks and volumes to ensure everything is cleaned up
echo "Networks:"
docker network ls

echo "Volumes:"
docker volume ls
