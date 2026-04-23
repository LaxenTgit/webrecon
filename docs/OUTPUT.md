```
# 📊 WebRecon Sample Outputs

Bu dosya, WebRecon aracının üretebileceği örnek çıktıları gösterir.

---

## 🎬 Terminal Output (scanme.nmap.org)

```

🔍 WebRecon Enterprise v3.0
Target: [https://scanme.nmap.org](https://scanme.nmap.org)

[+] Port 80 OPEN
[+] Port 443 OPEN

[+] Directory found: robots.txt (200)
[+] Directory found: admin/ (403)

[+] Scan completed | LOW (25/100)

📁 reports/report.json
📁 reports/report.html

````

---

## 📈 JSON Report (example)

```json
{
  "target": "https://scanme.nmap.org",
  "modules": {
    "ports": [80, 443],
    "directories": [
      { "path": "robots.txt", "statusCode": 200 },
      { "path": "admin/", "statusCode": 403 }
    ],
    "technologies": ["Nginx"]
  },
  "risk_assessment": {
    "score": 25,
    "level": "LOW",
    "issues": [
      "HTTP port open (80)",
      "Directory exposure detected"
    ]
  }
}
````

---

## 🧪 Localhost Example

```
Target: http://localhost:3000

[+] Port 3000 OPEN
[+] Directory found: api/ (200)
[+] Directory found: admin/ (404)

Scan completed | MEDIUM (35/100)
```

---

## 🔍 Production Example

```
Target: https://example.com

[+] Port 80 OPEN
[+] Port 443 OPEN

[+] Directory found: wp-admin/ (301)
[+] Directory found: config/ (403)

Scan completed | HIGH (65/100)

Issues:
- WordPress detected
- Sensitive directory exposure
```

---

## 🚀 Usage

```bash
dotnet run https://scanme.nmap.org

# View outputs
cat reports/report.json
cat reports/report.html
```

---

## 🧠 Notes

* Output format may vary depending on target configuration
* Some endpoints may block scanning or return false negatives
* Tool uses best-effort reconnaissance (non-intrusive)

```
