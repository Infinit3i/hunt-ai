# 🛡️ Threat Hunting Artificial Intelligence - HUNT-AI 🕵️‍♂️💻

### **TL;DR:** *Runbook to find threats & track your hunt 🚀

HUNT-AI is your **digital hunting companion** using MITRE ATT&CK as a framework. This ensures that analysts cover all potential **attack paths** while keeping meticulous track of findings. 📝  
It guides your **threat hunting process**, offers **insightful tips**, and ensures you're following **best practices**.
Built with experience from **real-world security operations** and inspired by cyber security **knowledge** into **one central hub**. 🏆🔎  

---

## 🎯 Features & Benefits
✅ **Runbook** – Follow steps to optomize threat hunting.  
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

