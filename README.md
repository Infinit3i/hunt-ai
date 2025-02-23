# 🛡️ Threat Hunting Artificial Intelligence - HUNT-AI

## **TL;DR:** Runbook to find threats & track your hunt 🚀

---

## 🎯 **Key Features & Benefits**

- ✅ **Comprehensive Runbook** – A step-by-step guide designed to optimize your threat-hunting process and establish a **streamlined workflow**.  
- ✅ **Investigation Tracking** – Organize and document your investigations with an electronic **analyst notebook**, enabling efficient **data management** and **reference**.  
- ✅ **MITRE ATT&CK Integration** – Seamlessly mapped to **T-codes**, ensuring your analysis remains **structured**, **comprehensive**, and **actionable**.  
- ✅ **Pre-configured SIEM Queries** – Quickly identify **malicious activity** with **detection queries**, accelerating your response time and improving **threat visibility**.  
- ✅ **Insightful Tips & Best Practices** – Receive expert guidance and actionable advice to enhance your threat-hunting strategies and decision-making.  
- ✅ **Multi-Platform Support** – Compatible with **Windows**, **Linux**, and **macOS**, offering versatility with minimal setup and dependencies.  
- ✅ **Collaborative Features** – Work together with your team by syncing investigations using **Docker Compose** (coming soon), improving collaboration and shared insights.


---

<div align="center">
  <img src="https://git.infinit3i.com/matthew/Hunt-AI/raw/commit/4c3b0654cd4c5b94e8659f2d18f86e01b579ba87/Assets/threat_hunter.jpeg" alt="Threat Hunter" width="600">
</div>

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
