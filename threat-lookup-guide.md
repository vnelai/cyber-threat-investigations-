# Threat Lookup Guide
_A detailed guide on how I use open-source tools to investigate Indicators of Compromise (IOCs)._

This document explains **what each tool does**, **when I’d use it**, and (when applicable) **how I’ve used it in real projects** like phishing investigations and threat enrichment.

---

## 🔗 URLs & Domains

### 🟡 urlscan.io
- **What it does:** Loads a webpage in a sandbox and shows what happens — redirects, JavaScript calls, and third-party resources.
- **When I use it:** When I receive a suspicious link or domain (e.g., in a phishing email), and want to preview behavior without opening it in my own browser.
- **Example:** I used it in a phishing investigation where the email linked to a fake Microsoft login page. urlscan showed hidden redirects and iframe content loading from a Russian domain.

---

### 🟡 VirusTotal (URLs)
- **What it does:** Scans URLs across multiple AV engines and shows reputation and community feedback.
- **When I use it:** To validate if a link is already known to be malicious or flagged by security vendors.
- **Example:** A link in a fake invoice email had 7 engines flag it for malware delivery via drive-by download.

---

### 🟡 Cisco Talos Intelligence
- **What it does:** Provides domain and IP reputation, WHOIS, and DNS history.
- **When I use it:** To double-check the trustworthiness of a domain or confirm if it’s related to an APT or threat actor.
- **Pro tip:** It's great for correlating threat intel with open-source investigations.

---

### 🟡 Google Safe Browsing
- **What it does:** Lets me know if a URL is flagged for phishing or malware by Google’s detection systems.
- **When I use it:** As an early, high-trust second opinion on suspicious links.
- **Example:** Helped confirm that a phishing domain was flagged long before AV engines caught up.

---

### 🟡 Sucuri SiteCheck
- **What it does:** Scans a public site for malware, spam injection, defacements, or blacklist status.
- **When I use it:** If I want a website malware scan without needing to download anything.

---

## 🌍 IP Address Lookups

### 🔵 AbuseIPDB
- **What it does:** Crowdsourced abuse reporting for IPs (e.g., brute force, spam, port scans).
- **When I use it:** When an IP shows up in email headers or logs, and I want to know if it’s been reported before.
- **Example:** I found a phishing email traced back to an IP with over 1,200 abuse reports — mostly brute force and phishing activity.

---

### 🔵 ipinfo.io
- **What it does:** Gives IP geolocation, ASN (network owner), and hosting provider.
- **When I use it:** To figure out if an IP is part of a cloud provider, residential IP, or VPN.
- **Example:** Helped me confirm an attacker was using DigitalOcean servers for phishing infrastructure.

---

### 🔵 Greynoise
- **What it does:** Tells you if an IP is “internet background noise” — i.e., mass scanners or opportunistic probes.
- **When I use it:** When hunting through logs to deprioritize benign scanning behavior.
- **Example:** Found that an IP hitting my web honeypot was just Shodan crawling — not targeted.

---

### 🔵 IPQualityScore
- **What it does:** Analyzes IP risk, including likelihood of proxy/VPN, mobile device, or bot traffic.
- **When I use it:** When trying to assess if an IP is anonymized or coming from a botnet.

---

## 🧪 File Hashes

### 🟢 VirusTotal (hashes)
- **What it does:** Checks file hashes (SHA256, MD5, etc.) against known malware samples across AV vendors.
- **When I use it:** When I receive or observe a suspicious file and want to check if it’s already been flagged.
- **Example:** A fake PDF invoice attachment had a SHA256 hash that matched a known Emotet dropper.

---

### 🟢 Hybrid Analysis
- **What it does:** Sandboxes a file to observe behavior like file writes, registry changes, and C2 calls.
- **When I use it:** When I want to see what a file does without executing it myself.
- **Note:** Uploading public samples is safe, but avoid uploading private company files.

---

### 🟢 Joe Sandbox
- **What it does:** Deep behavioral analysis platform, including network, API, and memory traces.
- **When I use it:** When Hybrid Analysis doesn’t return enough detail.
- **Tip:** Their PDF and docx file analysis is strong.

---

### 🟢 Unpac.me
- **What it does:** Unpacks and analyzes obfuscated malware samples (e.g., UPX-packed executables).
- **When I use it:** When I find a packed binary that needs analysis but can’t run it myself.

---

## 📧 Email Addresses

### 🟠 EmailRep.io
- **What it does:** Analyzes reputation, deliverability, breaches, and fraud risk for email addresses.
- **When I use it:** When I want to assess if an email address is legit, spoofed, or previously seen in phishing.
- **Example:** Helped confirm a suspicious Gmail address was disposable and linked to scam attempts.

---

### 🟠 Have I Been Pwned
- **What it does:** Checks if an email address has appeared in public data breaches.
- **When I use it:** To explain how an attacker might be targeting someone based on breach exposure.

---

### 🟠 Hunter.io
- **What it does:** Finds professional email addresses tied to domains.
- **When I use it:** To verify whether a sender matches the company they claim to be from.

---

### 🟠 Email Header Analyzer (MXToolbox)
- **What it does:** Visualizes email headers to help trace the sending server and origin IP.
- **When I use it:** In phishing investigations to determine the true source of the email.
- **Example:** Found the email came from a VPS host in Europe, not the claimed U.S. company.

---

## 🛠️ Bonus Tools

### 🧩 CyberChef
- **What it does:** Swiss Army knife for decoding, encoding, hashing, regex, XOR, Base64, etc.
- **When I use it:** Constantly. Useful for extracting obfuscated strings or decoding payloads in phishing URLs.

---

### 🧩 WHOIS Lookup
- **What it does:** Shows domain registration info — who registered it, when, and where.
- **When I use it:** To check if a domain is newly created, which is often a phishing red flag.

---

### 🧩 URL Decoder
- **What it does:** Decodes percent-encoded URLs (e.g., `%3A%2F%2F` becomes `://`).
- **When I use it:** When URLs in phishing emails are obfuscated to avoid detection.

---

### 🧩 SHA256 Hash Generator
- **What it does:** Creates a hash of a file or string.
- **When I use it:** To generate a hash before searching VirusTotal or sharing safely.

---

### 🧩 Regex101
- **What it does:** Live regex tester with explanations and match highlighting.
- **When I use it:** For extracting IOCs from logs, emails, or HTML.

---

## 📚 How This Fits Into My Workflow

These tools are the backbone of my day-to-day analysis. I use them to:
- Investigate phishing emails (see: [phishing-analysis/project-01-email-headers](../phishing-analysis/project-01-email-headers))
- Enrich IOCs found in logs or sandbox reports
- Document threat actor infrastructure and campaign patterns

When I’m reviewing security alerts, building detection rules, or writing reports, this toolkit is open in the background 100% of the time.
