# 📂 IOC Enrichment – Project 01: Email Header Investigation

This file documents the enrichment results for the IP address extracted from the suspicious email analyzed in `email01_header_analysis.txt`.

---

## 🔍 Enriched IOC: IP Address `57.103.77.23`

### ✅ Summary Table

| Source        | Result |
|---------------|--------|
| **AbuseIPDB** | ❌ Not found in database. No known abuse reports. |
| **IPinfo.io** |  
• ISP: Apple Inc.  
• Hostname: `npq-east2-cluster1-host4-snip4-10.eps.apple.com`  
• Geolocation: Maiden, North Carolina, USA  
• ASN: AS714 (Apple)  
• Privacy: `true` → Apple masks real sender IP  
• Abuse Contact: `abuse@apple.com` |
| **GreyNoise** |  
• No mass scanning observed in the past 24 hours.  
• ⚠️ Suggests possible **targeted delivery** vs. random spam. |

---

## 🧠 Interpretation

- This IP is part of **Apple’s iCloud Mail infrastructure**.
- The phishing email was **not spoofed** — it came from a legitimate iCloud address, either attacker-controlled or compromised.
- This tactic helps attackers **bypass SPF/DKIM/DMARC** checks and increase trust.
- **Conclusion:** The sender hid behind trusted Apple mail servers. The infrastructure itself is legitimate — the abuse comes from account misuse, not the IP.

---

## 💡 Tactic Observed

**Phishing tactic:** Use a real email provider (like iCloud or Gmail) so the message passes authentication and looks trustworthy.

---
