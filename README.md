Here's your **enhanced** `README.md` with **more details**, **more emojis**, and a **cleaner layout** to engage readers better! 🚀🔥

---


# 🛡️ Threat Hunting Artificial Intelligence - HUNT-AI 🕵️‍♂️💻

### **TL;DR:** *Find threats & track your hunt, boosting efficiency by **5x**!* 🚀

HUNT-AI is your **digital hunting companion**, ensuring that analysts cover all potential **attack paths** while keeping meticulous track of findings. 📝  
It guides your **threat hunting process**, offers **insightful tips**, and ensures you're following **best practices**.

Built with experience from **real-world security operations** and inspired by courses like **SEC504**, **FOR508**, and **13Cubed**, this tool consolidates **elite knowledge** into **one central hub**. 🏆🔎  

---

## 🎯 Features & Benefits
✅ **Track Your Investigations** – Organize your hunts and keep notes in an electronic **analyst notebook**.  
✅ **MITRE ATT&CK Integration** – Direct mapping to **T-codes**, keeping your analysis **structured** and **actionable**.  
✅ **SIEM Queries** – Run pre-configured **detection queries** for faster identification of **malicious activity**.  
✅ **Multi-Platform Support** – Runs on **Windows, Linux, and macOS** with minimal dependencies.  
✅ **Collaborative** – Sync investigations with your team via **Docker-compose** (coming soon).  

---

<div align="center">
  <img src="https://git.infinit3i.com/matthew/Hunt-AI/raw/commit/4c3b0654cd4c5b94e8659f2d18f86e01b579ba87/Assets/threat_hunter.jpeg" alt="Threat Hunter" width="600">
</div>

---

## 🛠️ Minimum Requirements  
- 🧠 **1 brain cell**  
- 🖥️ **PC** with at least a 🐹 (or better)  
- **Python 3.x** installed
- Docker Compose v2
- Docker

---

## 🔧 Dependencies  
Before running, make sure you have the following installed:

✅ **Python** (3.x or higher) → [Download Python](https://www.python.org/downloads/)  
✅ **Docker** (for containerized execution) → [Download Docker](https://www.docker.com/get-started/)  

> **💡 Note:**  
> If you’re new to Docker, follow the **[official installation guide](https://docs.docker.com/get-docker/)** to set it up on **Windows, macOS, or Linux**.

---

## 🚀 Quick Start Guide

1️⃣ **Download ZIP** 📦 (top right of GitHub page)  
2️⃣ **Extract** `Hunt-AI.zip`  
3️⃣ **Navigate to the folder**:
   `cd hunt-ai/`

```bash
docker build -t hunt-ai .
docker run -d -p 31337:31337 hunt-ai
sleep 2 && google-chrome http://localhost:31337 &
```


&nbsp;


## 📌 Roadmap / TODOs
- [ ] allow all tactics and techniques to be selected and show on the left side of the screen
- [ ] technique pages - verify tags, spl queries, clearing, event codes
- [ ] Knowledge DIR --> t-codes
- [ ] **Advanced Search** - Quickly retrieve relevant **hunt data**.  
- [ ] **Notebook Enhancements** - Track **IP addresses**, **domains**, **programs**, and **notes** easily.  
- [ ] **Notebook Exports** - Convert investigations into **PowerPoint** and **network diagrams**.  
- [ ] **Encrypted Notebook** - Securely store investigation **data & logs**.
- [ ] T-code - pass the hash - is local account

      block these for pass the has
      S-1-5-113: NT AUTHORITY\Local account
      S-1-5-114: NT AUTHORITY\Local account in Administrators group

      pass the pass (word) - wdigest, live, tspkg, kerberos - SeDebugPrivilege or SYSTEM priviledges





add values judge soc anlaysts

```
Time to detection
Time to resolution
Escalation rate
False positive rate
Incident recurrence rate
Compliance with SLAs
Team productivity & efficiency
Customer or stakeholder satisfaction

```


































---

## 🔬 Running Tests  
To verify that everything is working:  
```bash
python -m unittest discover Testing
```

---

# 📝 Changelog 📜  


## ✅ 1.1.5 (2025/02/19) 🚀  
- [X] added the basics of the search feature
- [X] add url_id to all tactics and get all tactics and techniques to link to their pages in the top left
- [X] **Windows Setup Guide** - Improve installation steps for **Windows users**.  
- [X] **Docker Integration** - Sync investigations with **team servers**.  
- [X] **Intel Additions** - Added new intelligence updates 🔍  
- [X] **Updated T1021** - Improvements and refinements 🛠️  
- [X] **Installation Improvements** - Changed installation process from Python to shell script ⚡  
- [X] **Enhanced Log Tracking** - Ensured `source` and `destination` fields are correctly handled in logs 📜  
- [X] **Setup Optimization** - Shortened and improved setup steps 🚀  
- [X] **Multi-Platform Support** - Added Windows and Linux setup instructions 💻  

## ✅ 1.1.4 (2025/02/16) 🚀  
- [X] **Checklist System** - allow hunt execution steps to be checked and clearing steps 
- [X] **T-code classification** - Better organization by **techniques & attacks**.  
- [X] **MITRE ATT&CK Mapping** - Better 
- [X] **visual representation** of tactics & techniques.  
- [X] **Massively expanded T-code coverage** 📌  
  - Added **over 20 new T-code technique files** 🛠️  
  - Ensured **each technique follows the updated template** 📜  
- [X] **Refined and optimized attack mappings** 🔗  
- [X] **Fixed missing technique displays** 🖥️  
- [X] **Improved tactic-lookup functionality** 🔍  
- [X] **Ensured correct association of techniques under tactics** 🏗️  
- [X] **Optimized technique loading and JSON structure** ⚡  
- [X] **Improved UI consistency for technique pages** 🎨  

## ✅ 1.1.3 (2025/02/14) 🎉  
- [X] Recreate the **technique template section** 🏗️  
- [X] Allow **multiple Splunk sections** 🔍  
- [X] Ensure **themes display correctly** 🎨  
- [X] Show **selected tactics in the top left** 📌  
- [X] Update & refine **theme styles** 🎭  
- [X] Ensure **background spans the entire page** 🌌  
- [X] Display **techniques like tactics (checkbox system)** ✅  
- [X] Group **techniques under their selected tactics** 📊  
- [X] Fix **gradient viewport issue** 🎨  
- [X] Optimize **checkbox alignment in grids** 🔲  

## ✅ 1.1.2  
- [X] Add **T-codes** to enhance **attack mapping** 🔗  

## ✅ 1.1.1 (2024/11/28)  
- [X] Update **methodology page** 📝  

## ✅ 1.1.0 (2024/11/27)  
- [X] Convert **CLI-based system** to a **web-based interface** 🌐  

## ✅ 1.0.5 (2024/11/26)  
- [X] Implement **search functionality** 🔎  
- [X] Add `common_ui.py` for **reusable UI components** 🏗️  

## ✅ 1.0.4 (2024/11/25)  
- [X] Create **analyst notebook** 📖  
    - [X] Track **IP addresses** 🌍  
    - [X] Store **domains** 🔗  
    - [X] Add **notes** 📝  
    - [X] Log **programs used** 💻  
- [X] Add **About section** ℹ️  
    - [X] Include `start.me` links 🌎  
    - [X] Link to **official website** 🔗  

## ✅ 1.0.3 (2024/11/24)  
- [X] Implement **highlighting & marking features** 🖍️  
- [X] Add **emojis** to improve UI ✨  
- [X] Simplify **backend logic** for efficiency ⚡  

## ✅ 1.0.0 (2024/11/23)  
- [X] **Initial Release** 🎉  
