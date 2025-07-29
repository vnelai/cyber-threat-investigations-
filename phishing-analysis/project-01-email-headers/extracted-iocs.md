# 📦 Extracted IOCs – Project 01: Email Header Investigation

This file contains all Indicators of Compromise (IOCs) extracted from the email header and image attachment.

---

## 📄 Source
- Header file: `email01_header_analysis.txt`
- Extraction method: Manual review + terminal commands (see `playbooks/phishing-response-playbook.md`)

---

## 🧩 IOC Table

| Type          | Value                          | Notes                                                                 |
|---------------|--------------------------------|-----------------------------------------------------------------------|
| IP Address    | 57.103.77.23                   | Origin IP from `Received:` header – belongs to Apple infrastructure  |
| Email Address | `kumar391715vz1@icloud.com`      | Real iCloud sender – not spoofed                                      |                                |
| Phone Number  | +1 (801) 614-7113              | Appeared inside image attachment                                        |
| Attachment    | phishing-email-01-screenshot.png | Screenshot of a fake email body — contains social engineering lure    |

---

## 💡 Notes

- IP was enriched (see `ioc-enrichment.md`)
- Attachment hash not yet generated — add if needed for YARA rules
- No URLs were found in this email

