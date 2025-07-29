# 🧠 Analysis Notes – Project 01: Phishing Email Header Investigation

This document captures my thoughts, reasoning, and conclusions during the investigation of a phishing email that contained no text body — only a PNG image with a suspicious phone number.

---

## 📌 Initial Impressions

- The email was unusual: no text, no subject, and no links — just a single image.
- This made it feel more like **reconnaissance** than a typical phishing attempt.
- It triggered curiosity about whether it was a **bait tactic** or test for active inboxes.

---

## 🕵️ Observations

- **Header Analysis**
  - Passed SPF, DKIM, and DMARC ✅
  - No spoofing observed — the sender domain was `@icloud.com`
  - Source IP `57.103.77.23` traced to Apple infrastructure

- **Image Content**
  - Screenshot of a fake email
  - Included a **US-based phone number** (`+1 (801) 614-7113`)
  - No clickable elements — just an image

- **Behavioral Indicators**
  - Not mass spam (per GreyNoise)
  - IP is clean, suggesting **account misuse** (attacker using legitimate service)
  - Phone number linked to multiple robocall/spam reports

---

## 🎯 Hypothesis

This is likely a **low-effort bait or validation email** sent from a real iCloud account to:

- Check if the email address is active (if image is loaded)
- Entice a manual call-back via the phone number
- Avoid detection by using an **image-only tactic** that bypasses URL scanners and phishing filters

---

## 🔒 Defensive Mindset: If This Reached a User

- Many users would not recognize this as phishing due to the lack of obvious indicators
- Email would pass through most secure gateways (SPF/DKIM/DMARC all pass)
- **Biggest risk**: a victim calling the number and falling into a vishing scam or account verification trap

---

## 🧩 Questions Raised

- Who controls the iCloud email?
- Was the account compromised, or was it created by the attacker?
- Is the phone number part of a larger scam campaign?

---

## 🧠 Lessons Learned

- **Attackers increasingly abuse trusted services** (iCloud, Gmail) to avoid being flagged
- A phishing attempt doesn’t need links or malware — **social engineering through images is enough**
- Image-only emails may **bypass filtering**, making them harder to catch
- Even “clean” infrastructure can carry **malicious intent** if misused by attackers

---


