# Create virtual environment if it doesn't exist
if (-Not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..."
    python -m venv venv
}

# Activate the virtual environment
Write-Host "Activating virtual environment..."
& .\venv\Scripts\Activate.ps1

# Upgrade pip and install requirements
Write-Host "Installing requirements..."
pip install --upgrade pip
pip install -r requirements.txt

# Change directory to the parent folder and run start.py
Write-Host "Changing directory to parent and starting application..."
Set-Location ..
python start.py
