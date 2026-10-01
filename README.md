# 🛡️ PhishShield AI — Real-Time Gmail & Quishing Defense (v1.4)

**PhishShield AI** is an advanced Chrome Extension (Manifest V3) and Python FastAPI microservice that defends against modern email attack vectors directly inside Gmail Webmail:
- **Quishing (QR Code Phishing):** Computer vision decoding of embedded QR codes bypassing text filters.
- **Display-Name Impersonation:** Executive / brand spoofing from free webmail accounts.
- **Deceptive Hyperlinks & Lookalikes:** Real-time anchor text mismatch and typosquatting detection.
- **Psychological Urgency NLP:** Detects artificial urgency, deadline pressure, and coercion.
- **Active Safe Click Guard:** Halts navigation on malicious links and displays an interactive warning modal.
- **Expandable In-Line Forensic Drawer:** Detailed MITRE ATT&CK mapping, explainable additive scoring, and 1-click SOC JSON export.

---

## 🚀 Quick Start (Running & Demonstrating)

### Step 1: Start the Defense Microservice
Double-click [`start_backend.bat`](file:///C:/Users/kpsum/phishshield/backend/start_backend.bat) in `backend/` or run:
```powershell
cd C:\Users\kpsum\phishshield\backend
python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```
*Health check URL: http://127.0.0.1:8000/api/v1/health*

---

### Step 2: Load the Extension into Google Chrome
1. Open Google Chrome (or Edge / Brave) and navigate to `chrome://extensions`.
2. Toggle on **Developer mode** in the top-right corner.
3. Click the **"Load unpacked"** button.
4. Select the folder: `C:\Users\kpsum\phishshield\extension`.
5. The **PhishShield AI** shield icon will appear in your browser toolbar!

---

## 🧪 Interactive Presentation Demo (4 Test Scenarios)

Open [`demo_sandbox.html`](file:///C:/Users/kpsum/phishshield/extension/demo_sandbox.html) in Chrome (or click *"🧪 Open Demo Sandbox"* in the toolbar popup).

Use the top scenario switcher to demonstrate all capabilities:

1. **Scenario 1 (Safe):** GitHub security notice with valid headers  
   👉 Injects the 🟢 **Verified Safe** banner.
2. **Scenario 2 (Executive BEC / Display-Name Spoof):** "CEO John Smith" emailing from `@gmail.com` demanding urgent gift cards  
   👉 Injects the 🟡 **Caution** banner (`+30 pts: Display-Name Spoof`, `+20 pts: Financial Coercion`).
3. **Scenario 3 (Credential Harvester):** Microsoft 365 password expiry notice with lookalike domain (`micros0ft-login.top`), anchor text mismatch, and `.pdf.exe` attachment  
   👉 Injects the 🔴 **Critical Phishing Alert** banner. The body link is annotated with a red dashed border and warning badge!  
   👉 Click the link to trigger the **Safe Click Interceptor Modal**!
4. **🚨 Scenario 4 (Quishing - QR Code MFA Attack):** Fake IT re-enrollment notice with an embedded QR code  
   👉 The extension automatically **scans and decodes the QR code** using computer vision.  
   👉 Wraps the QR image in a glowing red **Quishing Radar Overlay**:  
   `🚨 QUISHING RADAR: Hidden URL Decoded: http://micros0ft-mfa-security.top/enroll`.  
   👉 Adds `+40 pts: Quishing Attack` to the score!  
   👉 Clicking the QR code image triggers the Click Guard interceptor!

---

## 📊 Expandable In-Line Forensic Drawer & SOC Export
- Click **"▼ Details"** on any injected banner to expand the in-line security report:
  - Exact points breakdown (`+40 Quishing`, `+35 Lookalike`, `+30 Display-Name Spoof`).
  - Active **MITRE ATT&CK** mapping (`T1566.002: Quishing`, `T1534: Impersonation`).
  - Click **"📥 Export SOC Report (JSON)"** to download the structured incident JSON file!
