# 🛡️ Phishing Response Playbook

This playbook outlines a structured process for analyzing and responding to suspected phishing emails. 
It’s designed for SOC analysts, IR teams, or personal use during threat investigations.

---

## 🎯 Objectives

- Confirm whether the email is malicious
- Extract and enrich indicators (IP, domain, URL, attachments)
- Assess impact and scope
- Document findings and actions taken

---

## 🧭 Step-by-Step Workflow

### 1️⃣ Initial Triage

| Task | Tool/Notes |
|------|------------|
| Check subject line and sender address | Look for spoofing, misspellings, urgency |
| View email headers | Use [MXToolbox](https://mxtoolbox.com/EmailHeaders.aspx) for quick triage, then parse manually for deeper analysis |
| Extract links and attachments | Do not click — extract safely | See below for how to do this 👇 |
---

### 2️⃣ IOC Extraction

| Indicator | How to Extract |
|-----------|----------------|
| URLs/domains | Hover over links or inspect HTML source |
| IP addresses | From `Received:` fields in email headers |
| File hashes | Use SHA256 hash generator (if attachments) |
| Email addresses | Sender, Reply-To, Return-Path |
| Attachment name| May hint at social engineering |
| URLs	| In the body (if any visible or behind images) |
| Phone # | ☎️ Phone number  |

---

### 3️⃣ IOC Enrichment

| IOC Type | Tools |
|----------|-------|
| URL/domain | [VirusTotal](https://virustotal.com), [urlscan.io](https://urlscan.io), [Talos Intelligence](https://talosintelligence.com) |
| IP address | [AbuseIPDB](https://abuseipdb.com), [ipinfo.io](https://ipinfo.io), [Greynoise](https://viz.greynoise.io) |
| Email | [EmailRep.io](https://emailrep.io), [HaveIBeenPwned](https://haveibeenpwned.com) |
| WHOIS | [who.is](https://who.is), [DomainTools](https://whois.domaintools.com) |
| Hashes | [VirusTotal], [Hybrid Analysis], [JoeSandbox] |
| Phone# | [Google Search], [That’sThem](https://thatsthem.com/), [Sync.ME](https://sync.me/), [ScamNumbers.info](https://scamnumbers.info/), [Robokiller Lookup](https://lookup.robokiller.com/), [OSINT Combine Phone Lookup List](https://www.osintcombine.com/phone-number-osint) |

---

### 4️⃣ Analysis & Risk Assessment

| Question | Notes |
|----------|-------|
| Is the sender spoofed or lookalike? | Check SPF/DKIM headers and domain age |
| Is the URL serving malware or credential phishing? | Use sandbox analysis and screenshots |
| Is this a known campaign or APT tool? | Check community comments on VirusTotal |
| Does it target me specifically? | Look for personalization, internal context |

---

### 5️⃣ Document & Report

| Action | Deliverable |
|--------|-------------|
| Summarize findings | `README.md` in project folder |
| List all IOCs | `iocs.md` file with enrichment results |
| Attach screenshots | Save in `screenshots/` folder |
| MITRE mapping | e.g., `T1566.001 – Spearphishing Attachment` |
| Timeline or timeline notes | Optional: markdown table or JSON object |

---

## 🧠 MITRE ATT&CK Techniques Often Seen in Phishing

| TID | Name |
|-----|------|
| T1566.001 | Spearphishing Attachment |
| T1566.002 | Spearphishing Link |
| T1204.001 | User Execution: Malicious Link |
| T1059 | Command and Scripting Interpreter |
| T1003 | Credential Dumping *(if successful login bait)*

---

## 📎 Projects That Use This Playbook

This playbook was used as a guide during the following investigations:

- [Phishing Investigation #1 – Suspicious Invoice Email](../phishing-analysis/project-01-email-headers/README.md)


---

## ✅ Final Response Options (depending on context)

| Action | When to Take It |
|--------|------------------|
| Block domain/IP in firewall or EDR | IOC confirmed malicious |
| Notify impacted users | If phishing was clicked or downloaded |
| Report to platform or host | e.g., report phishing to registrar or Gmail |
| Submit sample to sandbox or sharing platform | e.g., VirusTotal, abuse.ch, URLHaus |
| Update internal documentation or playbook | After handling new or interesting case |

---

📌 This playbook will evolve as I complete more investigations and learn from real-world cases.
