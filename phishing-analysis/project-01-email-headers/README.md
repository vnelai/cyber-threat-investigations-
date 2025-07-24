# 📧 Phishing Email Investigation – Project 01

## 🕵️ Overview

This case analyzes a suspicious email that contained **no text body** and only a **PNG image attachment** — a screenshot of a fake email. Using a mix of open-source tools and manual inspection, I investigated the source, identified IOCs, and enriched them to understand the intent and infrastructure behind the message.

![Phishing Email Screenshot](screenshots/phishing-email-01-screenshot.png)
---

## 🧰 Tools Used

- [MXToolbox](https://mxtoolbox.com/) — email header visualization
- [AbuseIPDB](https://abuseipdb.com/) — IP reputation check
- [IPinfo.io](https://ipinfo.io/) — IP geolocation and privacy info
- [GreyNoise](https://viz.greynoise.io/) — checks if IP is scanning the internet
- Terminal commands on macOS (with `grep`) — metadata & IOC extraction

---

## 🧪 Steps Taken

1. **Header Analysis**
   - Raw headers saved to: [`email01_header_analysis.txt`](./email01_header.txt)
   - MXToolbox results screenshot: [`screenshots/mxtoolbox-header.png`](./screenshots/mxtoolbox-header.png)

----
2. **IOC Extraction**
   - IOC list: IP, email address, phone number, attachment
   - Extraction commands saved in: [`playbook-commands.md`](./playbook-commands.md)

3. **IOC Enrichment**
   - IP address checked via AbuseIPDB, IPinfo, and GreyNoise
   - Results documented in: [`ioc-enrichment.md`](./ioc-enrichment.md)

4. **Analysis Notes**
   - Full investigative thinking and inferences: [`analysis-notes.md`](./analysis-notes.md)

---

## 🔍 Key Findings

- ✅ The sender email (`kumar391715vz1@icloud.com`) is **not spoofed** — it passed SPF, DKIM, and DMARC
- 🛡️ IP address (`57.103.77.23`) is part of **Apple infrastructure**
- 🧊 The sender likely used iCloud Mail to mask their identity behind Apple’s infra
- 🧷 No links or text — only an **image attachment** with a **US-based phone number**
- 🎯 Likely a **recon/bait tactic** to test if this email address is active before targeting further

---

## 📚 What I Learned

- Spoofing isn't always used — **real email services like iCloud or Gmail** can be abused
- MXToolbox is great for quick analysis, but manual header parsing is essential for deep dives
- Safe IOC enrichment relies on public data — avoid uploading private samples
- Even a **silent phishing email** can reveal attacker intent when analyzed closely

---

## ✅ Next Steps

- Write detection rules (Sigma/YARA) based on pattern
- Submit safe IOCs (like the phone number or IP) to OSINT platforms
- Track similar campaigns and create a threat cluster
