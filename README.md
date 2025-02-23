# 🛡️ Threat Hunting Artificial Intelligence - HUNT-AI

<div align="center">
  <img src="https://git.infinit3i.com/matthew/Hunt-AI/raw/commit/4c3b0654cd4c5b94e8659f2d18f86e01b579ba87/Assets/threat_hunter.jpeg" alt="Threat Hunter" width="400">
</div>

![example workflow](https://github.com/github/docs/actions/workflows/main.yml/badge.svg)

### 🎯 **Key Features & Benefits**

- ✅ **Comprehensive Runbook** – A step-by-step guide designed to optimize your threat-hunting process and establish a **streamlined workflow**.  
- ✅ **Investigation Tracking** – Organize and document your investigations with an electronic **analyst notebook**, enabling efficient **data management** and **reference**.  
- ✅ **MITRE ATT&CK Integration** – Seamlessly mapped to **T-codes**, ensuring your analysis remains **structured**, **comprehensive**, and **actionable**.  
- ✅ **Pre-configured SIEM Queries** – Quickly identify **malicious activity** with **detection queries**, accelerating your response time and improving **threat visibility**.  
- ✅ **Insightful Tips & Best Practices** – Receive expert guidance and actionable advice to enhance your threat-hunting strategies and decision-making.  
- ✅ **Multi-Platform Support** – Compatible with **Windows**, **Linux**, and **macOS**, offering versatility with minimal setup and dependencies.  
- ✅ **Collaborative Features** – Work together with your team by syncing investigations using **Docker Compose** (coming soon), improving collaboration and shared insights.

---

### 🛠️ **Minimum Requirements**

- 🖥️ **PC** with at least **8 GB RAM**
- ⚙️ **Docker Compose v2**: [Download Docker Compose](https://docs.docker.com/compose/install/)
- [![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/get-started/)
- [![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://www.python.org/downloads/)

---

### 🚀 Quick Start Guide

1️⃣ **Download ZIP** 📦 (top right of GitHub page)  
2️⃣ **Extract** `Hunt-AI.zip`  
3️⃣ **Navigate to the folder**:
   `cd hunt-ai/`

```bash
docker build -t hunt-ai .
docker run -d -p 31337:31337 hunt-ai
sleep 2 && google-chrome http://localhost:31337 &
```
