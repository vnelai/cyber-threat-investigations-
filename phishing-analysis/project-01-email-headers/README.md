# 📨 Phishing Email Investigation: Suspicious Invoice Email

This project documents my hands-on analysis of a real phishing email I received in my personal inbox. I walked through each step of the investigation using open-source tools to trace the origin, evaluate the sender’s legitimacy, and enrich indicators like URLs and IPs.

---

## 🧭 Objective

- Perform a safe, end-to-end analysis of a phishing attempt
- Extract and enrich IOCs (URLs, domains, IP addresses, email sender)
- Use free CTI tools to validate suspicions
- Practice reporting and documentation for SOC workflows

---

## 🛠️ Tools Used

- [VirusTotal](https://virustotal.com)
- [urlscan.io](https://urlscan.io)
- [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
- [AbuseIPDB](https://abuseipdb.com)
- [ipinfo.io](https://ipinfo.io)
- [WHOIS Lookup](https://who.is)
- [CyberChef](https://gchq.github.io/CyberChef)

---

## 🧵 Investigation Summary

| Step | Action |
|------|--------|
| 🔍 1 | Collected full email headers from the suspicious message |
| 📬 2 | Parsed headers to identify Return-Path, Received IPs, and Mail Server |
| 🌐 3 | Extracted the embedded URL and analyzed it via urlscan.io and VirusTotal |
| 🌍 4 | Checked the sender IP and domain reputation (AbuseIPDB, ipinfo, Talos) |
| 🧾 5 | Created a list of all indicators (hashes, IPs, domains) in [iocs.md](./iocs.md) |
| 🧠 6 | Mapped techniques to MITRE ATT&CK (e.g., T1566.001 – Spearphishing Attachment) |

---

## 🖼️ Screenshots

See [`./screenshots/`](./screenshots/) for:
- Email header parser results
- urlscan.io report visual
- VirusTotal reputation scan

---

## 📌 Outcome

- Confirmed the email was a phishing attempt impersonating a cloud invoicing service
- Identified the domain was newly registered and hosted on an anonymous VPS provider
- Correlated sender IP with known abuse reports

---

## 🧠 What I Learned

- Email headers are a goldmine for tracing origin
- Simple open-source tools can reveal major red flags
- Reporting findings clearly is just as important as technical skills

---

📂 **Related Files**
- [iocs.md](./iocs.md) – Full list of IOCs + enrichment notes
- [`screenshots/`](./screenshots/) – Visual references used in the investigation
