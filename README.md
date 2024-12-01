# Threat Hunting Artificial Intelligence

**TLDR**: *find threats and be your electronic notebook to find the enemy **5x** quicker*

HUNT-AI helps threat hunting to make sure analysts are checking their boxes and observing all possibilities that an attacker can use on their terrain. This bot will help with managing how to threat hunting while giving helpful advice and keeping track of what you have looked at. All of this knowledge is made possible from the amazing support I have been given. learning from my current role, SEC504, FOR508, 13Cubed and many more have allowed me to give this amazing information in one central location.

<div align="center">
  <img src="https://git.infinit3i.com/matthew/Hunt-AI/raw/commit/4c3b0654cd4c5b94e8659f2d18f86e01b579ba87/Assets/threat_hunter.jpeg" alt="Threat Hunter" width="600">
</div>

## minimum requirements 
- 1 brain cell
- pc with atleast a 🐹

### Depenecies

#### [Python](https://www.python.org/downloads/)

# Directions

1. Download zip in top right
2. unzip Hunt-AI.zip
3. Go to path `*/hunt-ai/`
	- you should see `app.py`
4. Set Enviroment 
	- On Windows
		- `python -m venv hunt-ai`
		- `hunt-ai\Scripts\activate` -cmd
		- `.\hunt-ai\Scripts\Activate` - ps1
	- On macOS/Linux
		- `python3 -m venv hunt-ai`
		- `source hunt-ai/bin/activate`
5. Install requirements
	- On Windows & macOS/Linux
		- `pip install -r requirements.txt`
	- if that fails
		- `pip install flask flask_sqlalchemy flask_login`
6. Start
	- On Windows
		- `py.exe app.py`
	- On macOS/Linux
		- `python3 app.py`
		- `python3 app.py -h for help`
----


## Todo

#### IDEAS
- session management
- add more sections
- have ips be entered into links
- verify what links can be used
- checklist of all items
- searching


#### REFACTORING