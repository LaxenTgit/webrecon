# WebRecon Enterprise 🚀

[![.NET](https://github.com/LaxenTgit/WebReconEnterprise/actions/workflows/dotnet.yml/badge.svg)](https://github.com/LaxenTgit/WebReconEnterprise/actions)
[![License](https://img.shields.io/github/license/LaxenTgit/WebReconEnterprise)](LICENSE)

**Production-ready Web Reconnaissance Tool**  
DNS, Port Scan, SSL Analysis, Tech Detection, Directory Brute Force, JS Parsing

## ✨ Features
- ✅ **Async/Thread-Safe** (.NET 8)
- ✅ **Rate Limiting + WAF Bypass**
- ✅ **Risk Scoring** (Low/Medium/High)
- ✅ **HTML/JSON Reports**
- ✅ **Subdomain Enumeration**
- ✅ **Screenshot Capture**

## 🎬 Demo
![Demo](screenshots/demo.gif)

## 🚀 Quick Start (2dk)
```bash
# Kali/Debian/Ubuntu
curl -sSL https://raw.githubusercontent.com/LaxenTgit/WebReconEnterprise/main/install.sh | bash
webrecon https://example.com

# .NET
dotnet tool install --global WebReconEnterprise.Tool
webrecon https://scanme.nmap.org
