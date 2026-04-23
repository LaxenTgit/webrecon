# Installation Guide

## 🐧 Linux (Kali/Ubuntu/Debian)
```bash
# .NET 8 (one-time)
curl -sSL https://dot.net/v1/dotnet-install.sh | bash

# Clone & Run
git clone https://github.com/LaxenTgit/webrecon
cd webrecon
dotnet restore
dotnet run https://scanme.nmap.org
