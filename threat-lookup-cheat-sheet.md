# Cyber Threat Lookup Toolkit
_A curated list of tools I use to enrich and investigate IOCs (Indicators of Compromise)._

These are my go-to open-source and free tools for analyzing domains, IPs, hashes, and suspicious emails. I use them during phishing investigations, CTI research, and incident response workflows.

---

## 🔗 URLs & Domains
- [urlscan.io](https://urlscan.io) – Visual scan of webpages, shows redirects, JavaScript activity, and external calls
- [VirusTotal](https://www.virustotal.com) – Aggregates multiple AV engines and URL scanners to flag malicious links
- [Cisco Talos](https://talosintelligence.com) – Provides reputation and WHOIS data on domains and IPs
- [Google Safe Browsing](https://transparencyreport.google.com/safe-browsing/search) – Checks if a URL is flagged as phishing or malware
- [Sucuri SiteCheck](https://sitecheck.sucuri.net/) – Scans websites for malware, defacements, and blacklist status

---

## 🌍 IP Addresses
- [AbuseIPDB](https://abuseipdb.com) – Community-driven reports on abusive IP behavior (spam, brute force, etc.)
- [ipinfo.io](https://ipinfo.io) – Shows IP geolocation, ASN, ISP, and hosting type (residential, cloud, etc.)
- [Greynoise](https://viz.greynoise.io/) – Identifies whether an IP is part of internet-wide scanners or known actors
- [IPQualityScore](https://www.ipqualityscore.com/) – Risk analysis for IPs including proxy/VPN detection

---

## 🧪 File Hashes
- [VirusTotal](https://www.virustotal.com) – Upload or search file hashes to detect malware or suspicious files
- [Hybrid Analysis](https://www.hybrid-analysis.com) – Behavioral sandbox analysis for uploaded files and hashes
- [Joe Sandbox](https://www.joesandbox.com/) – Deep behavioral analysis of files, URLs, and documents (limited free tier)
- [Unpac.me](https://www.unpac.me/) – Deobfuscates and analyzes packed malware samples via hash or upload

---

## 📧 Email Addresses
- [EmailRep.io](https://emailrep.io/) – Provides reputation, breach exposure, and deliverability insights on email addresses
- [Have I Been Pwned](https://haveibeenpwned.com) – Checks if an email address was exposed in a known breach
- [Hunter.io](https://hunter.io) – Verifies whether a professional email exists and what domain it's associated with
- [Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx) – Parses and visualizes email headers to trace sender origin

---

## 🛠️ Bonus Tools
- [CyberChef](https://gchq.github.io/CyberChef) – Perform data decoding, encoding, encryption, and transformation
- [WHOIS Lookup](https://who.is) – Displays domain ownership and registration info
- [URL Decoder](https://meyerweb.com/eric/tools/dencoder/) – Decodes obfuscated or encoded URLs for analysis
- [SHA256 Hash Generator](https://emn178.github.io/online-tools/sha256.html) – Generates hashes for files or strings to check against malware databases
- [Regex101](https://regex101.com/) – Useful for extracting IOCs or parsing logs with regular expressions

---

## 🧠 Tip
This list pairs with my [Threat Lookup Guide](./threat-lookup-guide.md), which explains how and when I use each of these tools in real investigations.

