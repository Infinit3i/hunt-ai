# 🛡️ Threat Hunting Artificial Intelligence - HUNT-AI

<div align="center">
  <img src="https://git.infinit3i.com/matthew/Hunt-AI/raw/commit/4c3b0654cd4c5b94e8659f2d18f86e01b579ba87/Assets/threat_hunter.jpeg" alt="Threat Hunter" width="400">
</div>

<p align="center">
<br><br>
<a title="Releases" target="_blank" href="https://github.com/infinit3i/hunt-ai/releases"><img src="https://img.shields.io/github/release/infinit3i/hunt-ai.svg?style=flat-square&color=9CF"></a>
<a title="Downloads" target="_blank" href="https://github.com/infinit3i/hunt-ai/releases"><img src="https://img.shields.io/github/downloads/infinit3i/hunt-ai/total.svg?style=flat-square&color=blueviolet"></a>
<br>
<a title="Docker Pulls" target="_blank" href="https://hub.docker.com/r/b3log/siyuan"><img src="https://img.shields.io/docker/pulls/b3log/siyuan.svg?style=flat-square&color=green"></a>
<a title="Docker Image Size" target="_blank" href="https://hub.docker.com/r/b3log/siyuan"><img src="https://img.shields.io/docker/image-size/b3log/siyuan.svg?style=flat-square&color=ff96b4"></a>
<a title="Hits" target="_blank" href="https://github.com/infinit3i/hunt-ai"><img src="https://hits.b3log.org/infinit3i/hunt-ai.svg"></a>
<br>
<a title="Code Size" target="_blank" href="https://github.com/infinit3i/hunt-ai"><img src="https://img.shields.io/github/languages/code-size/infinit3i/hunt-ai.svg?style=flat-square&color=yellow"></a>
<a title="GitHub Pull Requests" target="_blank" href="https://github.com/infinit3i/hunt-ai/pulls"><img src="https://img.shields.io/github/issues-pr-closed/infinit3i/hunt-ai.svg?style=flat-square&color=FF9966"></a>
<br>
<a title="GitHub Commits" target="_blank" href="https://github.com/infinit3i/hunt-ai/commits/master"><img src="https://img.shields.io/github/commit-activity/m/siyuan-note/siyuan.svg?style=flat-square"></a>
<a title="Last Commit" target="_blank" href="https://github.com/infinit3i/hunt-ai/commits/master"><img src="https://img.shields.io/github/last-commit/siyuan-note/siyuan.svg?style=flat-square&color=FF9900"></a>
<br><br>
<a title="Twitter" target="_blank" href="https://x.com/infinit3i"><img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/b3logos?label=Follow&style=social"></a>
<a title="Discord" target="_blank" href="https://discord.gg/rzSTrk39yE"><img alt="Chat on Discord" src="https://img.shields.io/discord/805844406920806440?label=Discord&logo=Discord&style=social"></a>
</p>

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
