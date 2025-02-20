# Use a lightweight official Python image
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Set Python path to fix import issues
ENV PYTHONPATH=/app

# Copy only the requirements file first for better Docker caching
COPY app/Installation/requirements.txt /app/requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the entire project into the container
COPY . /app/

# Ensure SQLite database is stored in a persistent volume
VOLUME /app/instance

# Expose the required port (matches the one in start.py)
EXPOSE 31337

# Ensure the script has execution permissions
RUN chmod +x /app/app/start.py

# Set the entrypoint to run your application
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:31337", "app.app:app"]
