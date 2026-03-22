# 🛡️ NetShield – Complete Build & Deploy Guide

---

## 📁 Project Structure

```
netshield/
├── app.py                  ← Flask backend (all API logic)
├── requirements.txt        ← Python dependencies
├── Procfile                ← For Render deployment
├── render.yaml             ← Render config
├── netshield.db            ← Auto-created SQLite database
└── frontend/
    ├── index.html          ← Landing page
    ├── business.html       ← Business scan page
    └── tourist.html        ← Tourist Wi-Fi checker
```

---

## ✅ STEP 1 — Install Python & Dependencies

1. Make sure **Python 3.10+** is installed.
   Download from: https://www.python.org/downloads/

2. Open **Command Prompt** (or PowerShell) and navigate to the project:
   ```
   cd path\to\netshield
   ```

3. (Recommended) Create a virtual environment:
   ```
   python -m venv venv
   venv\Scripts\activate
   ```

4. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

---

## ✅ STEP 2 — Run Locally

```
python app.py
```

You'll see:
```
🛡️  NetShield backend running at http://localhost:5000
```

Open your browser → **http://localhost:5000**

> ⚠️ For real ARP scanning, run Command Prompt **as Administrator**:
> Right-click → "Run as Administrator" → then `python app.py`

---

## ✅ STEP 3 — Access from Other Devices on Same Wi-Fi

1. Find your Windows IP address:
   ```
   ipconfig
   ```
   Look for: **IPv4 Address** e.g. `192.168.1.5`

2. On your phone/tablet browser, open:
   ```
   http://192.168.1.5:5000
   ```

That's it — the full site works on any device on your local network!

---

## ✅ STEP 4 — Deploy to Render (Public Internet Access)

### 4a. Push to GitHub

1. Create a free account at https://github.com
2. Create a new repository called `netshield`
3. Run these commands in your project folder:
   ```
   git init
   git add .
   git commit -m "Initial NetShield commit"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/netshield.git
   git push -u origin main
   ```

### 4b. Deploy on Render

1. Go to https://render.com and create a free account
2. Click **"New" → "Web Service"**
3. Connect your GitHub account and select the `netshield` repository
4. Fill in:
   - **Name:** `netshield`
   - **Environment:** `Python`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
5. Click **"Create Web Service"**

Render will give you a URL like:
```
https://netshield.onrender.com
```

Open this URL from **any device, anywhere in the world!**

> ⚠️ Note: On Render's free tier, the ARP scan won't work (cloud servers have no local network). The tourist check and all other pages work perfectly. For real scans, run locally.

---

## 🔌 API Endpoints Reference

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Landing page |
| `/api/scan/business` | POST | Run real network scan |
| `/api/scan/tourist` | GET | Get tourist Wi-Fi list |
| `/api/devices` | GET | All scanned devices (DB) |
| `/api/alerts` | GET | All logged alerts (DB) |
| `/api/status` | GET | Server status + local IP |

---

## 🛠️ Troubleshooting

| Problem | Fix |
|---|---|
| No devices found in scan | Run `cmd` as Administrator |
| Backend offline error | Make sure `python app.py` is running |
| Can't access from phone | Check Windows Firewall — allow port 5000 |
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |

### Allow Port 5000 through Windows Firewall:
```
netsh advfirewall firewall add rule name="NetShield" dir=in action=allow protocol=TCP localport=5000
```

---

## 🚀 Future Enhancements

- [ ] Auto-block suspicious MAC addresses
- [ ] Email/SMS alerts for new devices
- [ ] ML-based anomaly detection
- [ ] Historical charts with Chart.js
- [ ] Mobile app with React Native
