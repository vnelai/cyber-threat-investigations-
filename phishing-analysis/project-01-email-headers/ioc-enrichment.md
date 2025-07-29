# 📂 IOC Enrichment – Project 01: Email Header Investigation

This file documents the enrichment results for the IP address extracted from the suspicious email analyzed in `email01_header_analysis.txt`.

---

## 🔍 Enriched IOC: IP Address `57.103.77.23`

### ✅ Summary Table

| Source        | Key Findings |
|---------------|--------------|
| **AbuseIPDB** | ❌ Not found in database. No abuse reports for this IP. |
| **IPinfo.io** | ✅ IP belongs to Apple Inc. Hostname: `npq-east2-cluster1-host4-snip4-10.eps.apple.com`. Geolocated in Maiden, NC. Privacy: `true` (sender masked). |
| **GreyNoise** | ⚠️ Not scanning internet recently → may indicate **targeted** delivery. |
| **MXToolbox** | ✅ Reverse DNS lookup shows Apple hostname. No blacklists triggered. TTL: 60 min. |

---

## 🖼️ Enrichment Screenshots

### 📸 MXToolbox Results

- Reverse DNS: `npq-east2-cluster1-host4-snip4-10.eps.apple.com`
- No blacklists detected  
- TTL: 60 minutes

**Image:**  
![MXToolbox Results](./screenshots/ioc-enrichment/mxtoolbox-header.png)

---

### 📸 AbuseIPDB

- IP: `57.103.77.23`
- ISP: Apple Inc.
- Status: Not listed  
- No reports of abuse

**Image:**  
![abuseipdb Results](./screenshots/ioc-enrichment/abuseipdb-ip-ioc.png)

---

### 📸 IPinfo.io

- ASN: AS714 — Apple Inc.
- Hostname: `npq-east2-cluster1-host4-snip4-10.eps.apple.com`
- Location: Maiden, NC, USA
- Abuse Contact: `abuse@apple.com`
- Privacy: True (Apple masks actual sender)

**Image:**  
![IPinfo.io Results](./screenshots/ioc-enrichment/1-ipinfo-ip-ioc.png)
![IPinfo.io Results](./screenshots/ioc-enrichment/2-ipinfo-ip-ioc.png)

---

### 📸 GreyNoise

- No recent scanning activity
- Likely a **targeted message** to this recipient

**Image:**  
![greynoise Results](./screenshots/ioc-enrichment/greynoise-ip-ioc.png)

---

## 🧠 Interpretation

- This IP belongs to **Apple’s iCloud Mail infrastructure**.
- The email was **not spoofed** — the attacker used a real iCloud account.
- This tactic allows the attacker to **pass SPF, DKIM, and DMARC** checks, gaining legitimacy.
- **Abuse** is tied to the account behavior, not the IP itself.

---

## 💡 Tactic Observed

**Phishing method:**  
Attackers are increasingly using real email providers (e.g., iCloud, Gmail) to evade filters and build trust. Messages sent from these providers often **pass all security checks**, making them harder to detect without content or behavioral analysis.

---
