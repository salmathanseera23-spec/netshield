from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import subprocess
import socket
import platform
import sqlite3
import re
import time
from datetime import datetime

app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)

DB_PATH = 'netshield.db'

# ── Database ───────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, mac TEXT, hostname TEXT, vendor TEXT,
        status TEXT, first_seen TEXT, last_seen TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT, level TEXT, timestamp TEXT
    )''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_alert(message, level='warning'):
    try:
        conn = get_db()
        conn.execute('INSERT INTO alerts (message, level, timestamp) VALUES (?,?,?)',
                     (message, level, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f'Alert log error: {e}')

# ── Network helpers ────────────────────────────────────────────────────────────
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return '192.168.1.1'

def get_subnet():
    ip = get_local_ip()
    parts = ip.split('.')
    return f"{'.'.join(parts[:3])}.0/24"

# ── Real nmap scan ─────────────────────────────────────────────────────────────
def run_nmap_scan():
    subnet = get_subnet()
    devices = []
    try:
        result = subprocess.run(
            ['nmap', '-sn', subnet],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout
        print("NMAP OUTPUT:\n", output)

        blocks = re.split(r'(?=Nmap scan report)', output)
        for block in blocks:
            if 'scan report' not in block:
                continue
            if 'Host is down' in block:
                continue

            ip = None
            hostname = 'Unknown'
            mac = 'N/A'
            vendor = 'Unknown'

            ip_match = re.search(r'scan report for (.+?) \((\d+\.\d+\.\d+\.\d+)\)', block)
            if ip_match:
                hostname = ip_match.group(1).strip()
                ip = ip_match.group(2).strip()
            else:
                ip_only = re.search(r'scan report for (\d+\.\d+\.\d+\.\d+)', block)
                if ip_only:
                    ip = ip_only.group(1).strip()
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = ip

            if not ip:
                continue

            mac_match = re.search(r'MAC Address: ([0-9A-Fa-f:]{17})\s+\((.+?)\)', block)
            if mac_match:
                mac = mac_match.group(1).upper()
                vendor = mac_match.group(2).strip()
            else:
                if ip == get_local_ip():
                    mac = 'This Device'
                    vendor = 'This Machine'

            devices.append({'ip': ip, 'mac': mac, 'hostname': hostname, 'vendor': vendor})

    except FileNotFoundError:
        return None, 'nmap is not installed or not in PATH'
    except subprocess.TimeoutExpired:
        return None, 'Scan timed out after 2 minutes'
    except Exception as e:
        return None, str(e)

    return devices, None

# ── Save devices ───────────────────────────────────────────────────────────────
def save_devices(devices):
    conn = get_db()
    now = datetime.now().isoformat()
    for d in devices:
        try:
            row = conn.execute('SELECT id FROM devices WHERE ip=?', (d['ip'],)).fetchone()
            if row:
                conn.execute(
                    'UPDATE devices SET mac=?, hostname=?, vendor=?, last_seen=? WHERE ip=?',
                    (d['mac'], d['hostname'], d['vendor'], now, d['ip'])
                )
            else:
                conn.execute(
                    'INSERT INTO devices (ip,mac,hostname,vendor,status,first_seen,last_seen) VALUES (?,?,?,?,?,?,?)',
                    (d['ip'], d['mac'], d['hostname'], d['vendor'], 'known', now, now)
                )
            conn.commit()
            log_alert(f"Device seen: {d['hostname']} ({d['ip']}) — {d['vendor']}", 'info')
        except Exception as e:
            print(f'Device save error: {e}')
    conn.close()

# ── Security scoring ───────────────────────────────────────────────────────────
def score_network(devices):
    score = 100
    issues = []
    fixes = []

    unknown = [d for d in devices if d['vendor'] in ('Unknown', 'Unknown Vendor')]
    if unknown:
        score -= len(unknown) * 10
        issues.append(f'{len(unknown)} device(s) with unidentified vendor detected')
        fixes.append('Physically check all connected devices and remove unfamiliar ones')

    if len(devices) > 15:
        score -= 10
        issues.append(f'High device count ({len(devices)}) — large attack surface')
        fixes.append('Review all connected devices and disconnect unused ones')

    if len(devices) == 0:
        score = 45
        issues.append('No devices discovered — try running as Administrator')
        fixes.append('Right-click VS Code → Run as Administrator, then restart')

    issues.append('Router firmware version could not be verified remotely')
    fixes.append('Log into your router admin panel and check for firmware updates')
    issues.append('WPA3 encryption status unknown')
    fixes.append('Ensure your router uses WPA2 or WPA3 encryption (not WEP or Open)')
    score -= 10

    score = max(5, min(100, score))

    if score >= 75:
        risk, color = 'Low Risk', 'green'
    elif score >= 45:
        risk, color = 'Moderate Risk', 'orange'
    else:
        risk, color = 'High Risk', 'red'

    return score, risk, color, issues, fixes

# ── Real WiFi scan for tourist mode ───────────────────────────────────────────
def scan_wifi_networks():
    try:
        import pywifi
        from pywifi import const

        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        iface.scan()
        time.sleep(3)
        results = iface.scan_results()

        networks = []
        for net in results:
            ssid = net.ssid.strip()
            if not ssid:
                continue

            akm = net.akm[0] if net.akm else 0

            if akm == const.AKM_TYPE_NONE:
                encryption = 'Open (No Encryption)'
                status = 'danger'
                details = 'No encryption — all data is visible to anyone nearby. Classic rogue hotspot pattern.'
                tips = [
                    'Do NOT connect — your data is fully exposed',
                    'Use mobile data instead',
                    'Report to venue if this claims to be their network',
                ]
            elif akm in (const.AKM_TYPE_WPA, const.AKM_TYPE_WPAPSK):
                encryption = 'WPA (Outdated)'
                status = 'suspicious'
                details = 'WPA (older standard) can be cracked with modern tools. Treat as untrusted network.'
                tips = [
                    'Use a VPN if you must connect',
                    'Avoid logging into accounts or banking',
                    'Prefer mobile data for sensitive tasks',
                ]
            elif akm == const.AKM_TYPE_WPA2PSK:
                encryption = 'WPA2'
                status = 'safe'
                details = 'WPA2 encryption detected — current standard for WiFi security. Generally safe for normal use.'
                tips = [
                    'Safe for general browsing',
                    'Still avoid banking on shared networks',
                    'Use HTTPS websites only',
                ]
            else:
                encryption = 'WPA2/WPA3'
                status = 'safe'
                details = 'Modern encryption standard detected. This network appears to be well secured.'
                tips = [
                    'Safe for general browsing',
                    'Use HTTPS websites only',
                ]

            networks.append({
                'ssid': ssid,
                'status': status,
                'encryption': encryption,
                'signal': net.signal,
                'details': details,
                'tips': tips,
            })

        order = {'danger': 0, 'suspicious': 1, 'safe': 2}
        networks.sort(key=lambda x: order.get(x['status'], 3))
        return networks

    except Exception as e:
        print(f'WiFi scan error: {e}')
        return []

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('frontend', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('frontend', path)

@app.route('/api/scan/business', methods=['POST'])
def business_scan():
    print(f"[{datetime.now()}] Business scan started...")
    devices, error = run_nmap_scan()
    if error:
        return jsonify({'success': False, 'error': error}), 500
    save_devices(devices)
    score, risk, color, issues, fixes = score_network(devices)
    print(f"[{datetime.now()}] Scan complete. Found {len(devices)} devices.")
    return jsonify({
        'success': True,
        'score': score,
        'risk': risk,
        'color': color,
        'issues': issues,
        'fixes': fixes,
        'devices': devices,
        'device_count': len(devices),
        'subnet': get_subnet(),
        'scanned_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    })

@app.route('/api/scan/tourist', methods=['GET'])
def tourist_scan():
    networks = scan_wifi_networks()
    if not networks:
        return jsonify({'success': False, 'error': 'No WiFi networks found. Make sure WiFi is on.'}), 500
    return jsonify({'success': True, 'networks': networks})

@app.route('/api/devices', methods=['GET'])
def get_devices():
    conn = get_db()
    rows = conn.execute('SELECT * FROM devices ORDER BY last_seen DESC').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    conn = get_db()
    rows = conn.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 50').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        'status': 'online',
        'local_ip': get_local_ip(),
        'subnet': get_subnet(),
        'hostname': socket.gethostname(),
        'platform': platform.system(),
    })

if __name__ == '__main__':
    init_db()
    print('🛡️  NetShield backend running at http://localhost:5000')
    app.run(debug=True, host='0.0.0.0', port=5000)
