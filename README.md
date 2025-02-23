# 🛡️ Threat Hunting Artificial Intelligence - HUNT-AI

### **TL;DR:** Runbook to find threats & track your hunt 🚀

HUNT-AI is your **digital hunting companion** using MITRE ATT&CK as a framework. This ensures that analysts cover all potential **attack paths** while keeping meticulous track of findings. 📝  
It guides your **threat hunting process**, offers **insightful tips**, and ensures you're following **best practices**.
Built with experience from **real-world security operations** and inspired by cyber security **knowledge** into **one central hub**. 🏆🔎  

---

<div align="center">
  <img src="https://git.infinit3i.com/matthew/Hunt-AI/raw/commit/4c3b0654cd4c5b94e8659f2d18f86e01b579ba87/Assets/threat_hunter.jpeg" alt="Threat Hunter" width="600">
</div>

---

## 🎯 Features & Benefits
✅ **Runbook** – Follow steps to optomize threat hunting.  
✅ **Track Your Investigations** – Organize your hunts and keep notes in an electronic **analyst notebook**.  
✅ **MITRE ATT&CK Integration** – Direct mapping to **T-codes**, keeping your analysis **structured** and **actionable**.  
✅ **SIEM Queries** – Run pre-configured **detection queries** for faster identification of **malicious activity**.  
✅ **Multi-Platform Support** – Runs on **Windows, Linux, and macOS** with minimal dependencies.  
✅ **Collaborative** – Sync investigations with your team via **Docker-compose** (coming soon).  

---

## 🛠️ **Minimum Requirements**

- 🖥️ **PC** with at least **8 GB RAM**  
- 🐍 **Python 3.x**: [Download Python](https://www.python.org/downloads/)  
- ⚙️ **Docker Compose v2**: [Download Docker Compose](https://docs.docker.com/compose/install/)  
- 🐳 **Docker**: [Download Docker](https://www.docker.com/get-started/)

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

---

## 🔬 Running Tests  
To verify that everything is working:  
```bash
python -m unittest discover Testing
```
