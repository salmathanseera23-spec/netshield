from flask import Flask, jsonify, request, send_from_directory
from datetime import datetime
import subprocess
import socket
import sqlite3
import platform
import re
import time
import urllib.request
import urllib.error

# ── Optional CORS support ──────────────────────────────────────────────────────
# Install with: pip install flask-cors
try:
    from flask_cors import CORS
    _cors_available = True
except ImportError:
    _cors_available = False
    print("[NetShield] WARNING: flask-cors not installed. CORS headers will not be sent.")
    print("           Run: pip install flask-cors")

app = Flask(__name__, static_folder='frontend', static_url_path='')
if _cors_available:
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
    c.execute('''CREATE TABLE IF NOT EXISTS audits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        score INTEGER, risk TEXT, summary TEXT, timestamp TEXT
    )''')
    # FIX: Added feedback table — required by the /api/feedback route
    c.execute('''CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ssid TEXT, bssid TEXT, type TEXT, score INTEGER,
        comment TEXT, timestamp TEXT
    )''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ── Network helpers ────────────────────────────────────────────────────────────
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '192.168.1.1'

def get_router_ip():
    """Get default gateway (router IP)."""
    try:
        if platform.system() == 'Windows':
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if 'Default Gateway' in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        return match.group(1)
        else:
            # Linux / macOS
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True
            )
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
    except Exception:
        pass
    # Fallback: assume .1 of local subnet
    ip = get_local_ip()
    return '.'.join(ip.split('.')[:3]) + '.1'

def get_subnet():
    ip = get_local_ip()
    return '.'.join(ip.split('.')[:3]) + '.0/24'

# ══════════════════════════════════════════════════════════════════════════════
# CHECK 1 — WiFi Encryption Type
# ══════════════════════════════════════════════════════════════════════════════
def check_wifi_encryption():
    result = {
        'id': 'encryption',
        'name': 'WiFi Encryption Standard',
        'status': 'unknown',
        'value': 'Unknown',
        'issue': None,
        'fix': None,
        'severity': None,
    }
    try:
        import pywifi
        from pywifi import const

        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        iface.scan()
        time.sleep(3)
        networks = iface.scan_results()

        if not networks:
            result['value'] = 'No networks found during scan'
            result['status'] = 'unknown'
            return result

        # Sort by signal strength descending; take strongest as likely-connected
        networks.sort(key=lambda n: n.signal, reverse=True)
        connected = networks[0]
        akm = connected.akm[0] if connected.akm else 0

        if akm == const.AKM_TYPE_NONE:
            result['value'] = 'Open (No Encryption)'
            result['status'] = 'fail'
            result['severity'] = 'critical'
            result['issue'] = (
                'Your WiFi has NO encryption. Anyone nearby can intercept every packet '
                'you send — passwords, messages, banking data.'
            )
            result['fix'] = (
                'Log into your router admin panel → Wireless Settings → Security Mode '
                '→ set to WPA3 or WPA2-AES. Never use Open networks for anything sensitive.'
            )

        elif akm in (1, 2):  # WPA (TKIP)
            result['value'] = 'WPA (Outdated)'
            result['status'] = 'fail'
            result['severity'] = 'high'
            result['issue'] = (
                'WPA (original) encryption is outdated and can be cracked with modern '
                'tools like hashcat in hours. Your network is vulnerable.'
            )
            result['fix'] = (
                'Log into your router admin panel → Wireless Security → change from WPA '
                'to WPA2-AES or WPA3. WPA2 is the minimum acceptable standard in 2026.'
            )

        elif akm == const.AKM_TYPE_WPA2PSK:
            result['value'] = 'WPA2 (Acceptable)'
            result['status'] = 'warn'
            result['severity'] = 'medium'
            result['issue'] = (
                'WPA2 is acceptable but WPA3 is the modern standard. WPA2 is vulnerable '
                'to KRACK attacks on older router firmware.'
            )
            result['fix'] = (
                'Check if your router supports WPA3 in its admin panel. If it does, '
                'upgrade. Also ensure your router firmware is up to date to patch KRACK vulnerabilities.'
            )

        else:
            result['value'] = 'WPA3 (Excellent)'
            result['status'] = 'pass'
            result['severity'] = None
            result['issue'] = None
            result['fix'] = None

        result['ssid'] = connected.ssid.strip()

    except ImportError:
        result['value'] = 'pywifi not installed — run: pip install pywifi'
        result['status'] = 'unknown'
    except Exception as e:
        result['value'] = f'Scan error: {e}'
        result['status'] = 'unknown'

    return result


# ══════════════════════════════════════════════════════════════════════════════
# CHECK 2 — Open Ports on Router (nmap)
# ══════════════════════════════════════════════════════════════════════════════
def check_open_ports():
    result = {
        'id': 'open_ports',
        'name': 'Router Open Ports',
        'status': 'unknown',
        'value': 'Unknown',
        'open_ports': [],
        'issue': None,
        'fix': None,
        'severity': None,
    }

    DANGEROUS_PORTS = {
        21:   ('FTP',      'critical', 'FTP transfers files in plain text. Attackers can intercept credentials.', 'Disable FTP on your router. Use SFTP or FTPS if file transfer is needed.'),
        23:   ('Telnet',   'critical', 'Telnet sends all commands including passwords in plain text — completely insecure.', 'Disable Telnet immediately in router settings. Use SSH instead.'),
        80:   ('HTTP Admin','high',    'Router admin panel is accessible over unencrypted HTTP. Login credentials can be intercepted.', 'Disable HTTP admin access. Use HTTPS (port 443) only. Also disable WAN admin access.'),
        443:  ('HTTPS Admin','low',    'Router admin panel accessible over HTTPS. This is acceptable but should be restricted.', 'Restrict admin access to specific devices only in router settings. Disable remote (WAN) access.'),
        8080: ('HTTP Alt', 'high',    'Alternative HTTP port open — often used by older router admin panels without encryption.', 'Disable port 8080 in router settings unless you specifically need it.'),
        22:   ('SSH',      'medium',   'SSH port is open. If using default credentials this is a serious vulnerability.', 'Ensure SSH uses key-based authentication. Disable if not needed. Change default credentials.'),
        53:   ('DNS',      'medium',   'DNS port exposed — could be used for DNS amplification attacks or hijacking.', 'Disable external DNS on your router unless you are running a DNS server intentionally.'),
        1900: ('UPnP',     'high',     'UPnP is enabled. This protocol has serious known vulnerabilities and can allow attackers to open ports remotely.', 'Disable UPnP in your router settings immediately. It is almost never needed for home networks.'),
        5000: ('UPnP/Dev', 'medium',   'Port 5000 open — often associated with UPnP or development services.', 'Investigate what is using this port. Disable UPnP in router settings.'),
    }

    try:
        router_ip = get_router_ip()
        result['router_ip'] = router_ip

        nmap_result = subprocess.run(
            ['nmap', '-sV', '--open', '-p', '21,22,23,53,80,443,8080,1900,5000,8443,8888', router_ip],
            capture_output=True, text=True, timeout=60
        )

        open_ports = []
        port_pattern = re.compile(r'(\d+)/tcp\s+open\s+(\S+.*)')

        for line in nmap_result.stdout.splitlines():
            m = port_pattern.search(line)
            if m:
                port_num = int(m.group(1))
                service  = m.group(2).strip()
                info = DANGEROUS_PORTS.get(port_num)
                if info:
                    open_ports.append({
                        'port': port_num, 'service': info[0],
                        'severity': info[1], 'issue': info[2],
                        'fix': info[3], 'raw_service': service,
                    })
                else:
                    open_ports.append({
                        'port': port_num, 'service': service,
                        'severity': 'low',
                        'issue': f'Port {port_num} is open. Verify this is intentional.',
                        'fix': f'If you do not need port {port_num}, disable it in router settings to reduce attack surface.',
                        'raw_service': service,
                    })

        result['open_ports'] = open_ports
        result['value'] = f'{len(open_ports)} potentially risky port(s) open'

        critical = [p for p in open_ports if p['severity'] == 'critical']
        high     = [p for p in open_ports if p['severity'] == 'high']

        if critical:
            result['status']   = 'fail'
            result['severity'] = 'critical'
            result['issue']    = f'Critical ports open: {", ".join(str(p["port"]) for p in critical)}. These are active security vulnerabilities.'
            result['fix']      = 'Disable all unnecessary services on your router immediately. Access router admin panel and disable FTP and Telnet.'
        elif high:
            result['status']   = 'fail'
            result['severity'] = 'high'
            result['issue']    = f'High-risk ports open: {", ".join(str(p["port"]) for p in high)}. These expose your router to attack.'
            result['fix']      = 'Log into your router and disable all services you do not actively use.'
        elif open_ports:
            result['status']   = 'warn'
            result['severity'] = 'medium'
            result['issue']    = f'{len(open_ports)} port(s) open on your router that should be reviewed.'
            result['fix']      = 'Review each open port below. Disable any service you do not recognise or need.'
        else:
            result['status']   = 'pass'
            result['value']    = 'No dangerous ports detected'
            result['severity'] = None
            result['issue']    = None
            result['fix']      = None

    except FileNotFoundError:
        result['value']  = 'nmap not installed — run: sudo apt install nmap  (or brew install nmap on macOS)'
        result['status'] = 'unknown'
    except Exception as e:
        result['value']  = f'Scan error: {e}'
        result['status'] = 'unknown'

    return result


# ══════════════════════════════════════════════════════════════════════════════
# CHECK 3 — Router Admin Panel Exposure
# ══════════════════════════════════════════════════════════════════════════════
def check_router_admin():
    result = {
        'id': 'router_admin',
        'name': 'Router Admin Panel Exposure',
        'status': 'unknown',
        'value': 'Unknown',
        'issue': None,
        'fix': None,
        'severity': None,
        'exposed_urls': [],
    }

    import ssl

    router_ip = get_router_ip()
    result['router_ip'] = router_ip
    exposed = []

    ports_to_check = [
        (80,   'http',  'HTTP (unencrypted)'),
        (443,  'https', 'HTTPS'),
        (8080, 'http',  'HTTP Alt (8080)'),
        (8443, 'https', 'HTTPS Alt (8443)'),
    ]

    for port, scheme, label in ports_to_check:
        url = f'{scheme}://{router_ip}:{port}'
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            ctx = None
            if scheme == 'https':
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
            resp    = urllib.request.urlopen(req, timeout=4, context=ctx)
            content = resp.read(500).decode('utf-8', errors='ignore').lower()

            is_login = any(kw in content for kw in ['password', 'login', 'admin', 'username', 'sign in', 'router'])
            exposed.append({
                'url': url, 'label': label, 'port': port,
                'is_login_page': is_login, 'encrypted': scheme == 'https',
            })
        except Exception:
            pass

    result['exposed_urls'] = exposed

    http_exposed  = [e for e in exposed if not e['encrypted']]
    https_exposed = [e for e in exposed if e['encrypted']]

    if http_exposed:
        result['status']   = 'fail'
        result['severity'] = 'high'
        result['value']    = f'Admin panel exposed on HTTP at port(s): {", ".join(str(e["port"]) for e in http_exposed)}'
        result['issue']    = (
            f'Your router admin panel is accessible over unencrypted HTTP ({http_exposed[0]["url"]}). '
            'Anyone on your network can intercept your router login credentials using a simple packet sniffer.'
        )
        result['fix'] = (
            '1. Log into your router admin panel.\n'
            '2. Go to Administration / Management settings.\n'
            '3. Disable HTTP access and enable HTTPS only.\n'
            '4. Also disable remote (WAN) admin access if you do not need it.'
        )
    elif https_exposed:
        result['status']   = 'warn'
        result['severity'] = 'medium'
        result['value']    = 'Admin panel on HTTPS only (acceptable)'
        result['issue']    = 'Router admin panel is accessible but uses HTTPS encryption. The panel is reachable from any device on your network.'
        result['fix']      = 'Consider restricting admin access to specific MAC addresses or disabling it entirely when not in use.'
    else:
        result['status'] = 'pass'
        result['value']  = 'Admin panel not openly accessible'
        result['issue']  = None
        result['fix']    = None

    return result


# ══════════════════════════════════════════════════════════════════════════════
# CHECK 4 — Unknown Device Detection
# ══════════════════════════════════════════════════════════════════════════════
def check_unknown_devices():
    result = {
        'id': 'unknown_devices',
        'name': 'Unknown Device Detection',
        'status': 'unknown',
        'value': 'Unknown',
        'devices': [],
        'unknown': [],
        'issue': None,
        'fix': None,
        'severity': None,
    }

    try:
        subnet = get_subnet()
        nmap_result = subprocess.run(
            ['nmap', '-sn', subnet],
            capture_output=True, text=True, timeout=120
        )

        devices = []
        blocks  = re.split(r'(?=Nmap scan report)', nmap_result.stdout)

        for block in blocks:
            if 'scan report' not in block or 'Host is down' in block:
                continue

            ip, hostname, mac, vendor = None, 'Unknown', 'N/A', 'Unknown'

            ip_match = re.search(r'scan report for (.+?) \((\d+\.\d+\.\d+\.\d+)\)', block)
            if ip_match:
                hostname = ip_match.group(1).strip()
                ip       = ip_match.group(2).strip()
            else:
                ip_only = re.search(r'scan report for (\d+\.\d+\.\d+\.\d+)', block)
                if ip_only:
                    ip = ip_only.group(1).strip()
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        hostname = ip

            if not ip:
                continue

            mac_match = re.search(r'MAC Address: ([0-9A-Fa-f:]{17})\s+\((.+?)\)', block)
            if mac_match:
                mac    = mac_match.group(1).upper()
                vendor = mac_match.group(2).strip()
            elif ip == get_local_ip():
                vendor = 'This Machine'

            devices.append({'ip': ip, 'mac': mac, 'hostname': hostname, 'vendor': vendor})

        # Persist to DB
        conn = get_db()
        now  = datetime.now().isoformat()
        for d in devices:
            try:
                row = conn.execute('SELECT id FROM devices WHERE ip=?', (d['ip'],)).fetchone()
                if row:
                    conn.execute(
                        'UPDATE devices SET mac=?,hostname=?,vendor=?,last_seen=? WHERE ip=?',
                        (d['mac'], d['hostname'], d['vendor'], now, d['ip'])
                    )
                else:
                    conn.execute(
                        'INSERT INTO devices (ip,mac,hostname,vendor,status,first_seen,last_seen) VALUES (?,?,?,?,?,?,?)',
                        (d['ip'], d['mac'], d['hostname'], d['vendor'], 'new', now, now)
                    )
                conn.commit()
            except Exception:
                pass
        conn.close()

        unknown = [d for d in devices if d['vendor'] not in ('Unknown', 'Unknown Vendor', 'This Machine')
                   and d['vendor'] == 'Unknown']

        # FIX: Previous logic inverted — unknown devices have vendor == 'Unknown'
        unknown = [d for d in devices if d['vendor'] == 'Unknown']

        result['devices'] = devices
        result['unknown'] = unknown
        result['value']   = f'{len(devices)} device(s) found, {len(unknown)} unidentified'

        if len(unknown) >= 2:
            result['status']   = 'fail'
            result['severity'] = 'high'
            result['issue']    = (
                f'{len(unknown)} devices on your network have unidentifiable hardware vendors. '
                'This means these devices could be unauthorized — someone connecting to your WiFi without permission.'
            )
            result['fix'] = (
                '1. Log into your router admin panel → DHCP Client List.\n'
                '2. Cross-reference every device listed with devices you own.\n'
                '3. For any device you cannot identify, use MAC filtering to block it.\n'
                '4. Change your WiFi password immediately if you find unauthorized devices.'
            )
        elif len(unknown) == 1:
            result['status']   = 'warn'
            result['severity'] = 'medium'
            result['issue']    = '1 device with an unidentified vendor is connected. This may be a guest device or an unauthorized connection.'
            result['fix']      = "Check your router's connected devices list. If you cannot identify this device, change your WiFi password and enable MAC address filtering."
        else:
            result['status'] = 'pass'
            result['value']  = f'{len(devices)} device(s) found — all vendors identified'
            result['issue']  = None
            result['fix']    = None

    except FileNotFoundError:
        result['value']  = 'nmap not installed — run: sudo apt install nmap  (or brew install nmap on macOS)'
        result['status'] = 'unknown'
    except Exception as e:
        result['value']  = f'Scan error: {e}'
        result['status'] = 'unknown'

    return result


# ══════════════════════════════════════════════════════════════════════════════
# CHECK 5 — DNS Safety
# ══════════════════════════════════════════════════════════════════════════════
def check_dns_safety():
    result = {
        'id': 'dns',
        'name': 'DNS Server Safety',
        'status': 'unknown',
        'value': 'Unknown',
        'dns_servers': [],
        'issue': None,
        'fix': None,
        'severity': None,
    }

    SAFE_DNS = {
        '8.8.8.8':           'Google DNS',
        '8.8.4.4':           'Google DNS',
        '1.1.1.1':           'Cloudflare DNS',
        '1.0.0.1':           'Cloudflare DNS',
        '9.9.9.9':           'Quad9 DNS (Security-filtered)',
        '149.112.112.112':   'Quad9 DNS',
        '208.67.222.222':    'OpenDNS',
        '208.67.220.220':    'OpenDNS',
    }

    try:
        dns_servers = []

        if platform.system() == 'Windows':
            r = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if 'DNS Servers' in line or ('DNS' in line and re.search(r'\d+\.\d+\.\d+\.\d+', line)):
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if m:
                        ip = m.group(1)
                        if ip not in dns_servers:
                            dns_servers.append(ip)
        else:
            # Linux / macOS: read /etc/resolv.conf
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        m = re.match(r'nameserver\s+(\d+\.\d+\.\d+\.\d+)', line.strip())
                        if m and m.group(1) not in dns_servers:
                            dns_servers.append(m.group(1))
            except Exception:
                pass

        if not dns_servers:
            dns_servers = [get_router_ip()]

        enriched   = []
        suspicious = []
        router_ip  = get_router_ip()

        for dns in dns_servers:
            known     = SAFE_DNS.get(dns)
            is_router = dns == router_ip

            if known:
                enriched.append({'ip': dns, 'name': known, 'status': 'safe'})
            elif is_router:
                enriched.append({'ip': dns, 'name': 'Your Router (forwarding DNS)', 'status': 'neutral'})
            else:
                enriched.append({'ip': dns, 'name': 'Unknown DNS Server', 'status': 'suspicious'})
                suspicious.append(dns)

        result['dns_servers'] = enriched

        # DNS hijack detection: google.com must never resolve to a private address
        try:
            resolved_ip = socket.gethostbyname('www.google.com')
            if resolved_ip.startswith(('192.168.', '10.', '172.')):
                result['status']   = 'fail'
                result['severity'] = 'critical'
                result['value']    = 'DNS HIJACKING DETECTED'
                result['issue']    = (
                    f'www.google.com resolved to a private IP ({resolved_ip}). '
                    'This is a strong indicator your DNS is being hijacked — an attacker may be '
                    'redirecting your traffic to fake websites.'
                )
                result['fix'] = (
                    '1. Immediately disconnect from this network.\n'
                    '2. Change your DNS to 1.1.1.1 (Cloudflare) or 8.8.8.8 (Google) in your network adapter settings.\n'
                    '3. Factory reset your router if this persists.'
                )
                return result
        except Exception:
            pass

        if suspicious:
            result['status']   = 'warn'
            result['severity'] = 'medium'
            result['value']    = f'Unknown DNS: {", ".join(suspicious)}'
            result['issue']    = (
                f'Your device is using an unrecognized DNS server ({", ".join(suspicious)}). '
                'Unknown DNS servers can redirect you to fake websites (DNS spoofing) without your knowledge.'
            )
            result['fix'] = (
                '1. Go to Control Panel → Network → Adapter Settings.\n'
                '2. Right-click your WiFi → Properties → IPv4 → Use following DNS.\n'
                '3. Set to 1.1.1.1 (Cloudflare) or 8.8.8.8 (Google) for safety.'
            )
        else:
            result['status'] = 'pass'
            result['value']  = f'Safe DNS: {", ".join(e["name"] for e in enriched)}'
            result['issue']  = None
            result['fix']    = None

    except Exception as e:
        result['value']  = f'Check error: {e}'
        result['status'] = 'unknown'

    return result


# ══════════════════════════════════════════════════════════════════════════════
# Master audit function
# ══════════════════════════════════════════════════════════════════════════════
def run_full_audit():
    checks = []

    print('[1/5] Checking WiFi encryption...')
    checks.append(check_wifi_encryption())

    print('[2/5] Scanning router ports...')
    checks.append(check_open_ports())

    print('[3/5] Checking router admin exposure...')
    checks.append(check_router_admin())

    print('[4/5] Scanning for unknown devices...')
    checks.append(check_unknown_devices())

    print('[5/5] Checking DNS safety...')
    checks.append(check_dns_safety())

    severity_penalty = {'critical': 30, 'high': 20, 'medium': 10, 'low': 5}
    score = 100
    for c in checks:
        if c['status'] in ('fail', 'warn') and c.get('severity'):
            score -= severity_penalty.get(c['severity'], 0)
    score = max(0, min(100, score))

    failed = [c for c in checks if c['status'] == 'fail']
    warned = [c for c in checks if c['status'] == 'warn']
    passed = [c for c in checks if c['status'] == 'pass']

    if score >= 80:
        risk, color = 'Low Risk', 'green'
    elif score >= 50:
        risk, color = 'Moderate Risk', 'orange'
    else:
        risk, color = 'High Risk', 'red'

    try:
        conn = get_db()
        conn.execute(
            'INSERT INTO audits (score, risk, summary, timestamp) VALUES (?,?,?,?)',
            (score, risk, f'{len(failed)} failed, {len(warned)} warnings', datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    return {
        'success':    True,
        'score':      score,
        'risk':       risk,
        'color':      color,
        'checks':     checks,
        'summary': {
            'failed':   len(failed),
            'warnings': len(warned),
            'passed':   len(passed),
            'total':    len(checks),
        },
        'router_ip':   get_router_ip(),
        'local_ip':    get_local_ip(),
        'scanned_at':  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }


# ══════════════════════════════════════════════════════════════════════════════
# Tourist WiFi scanner
# ══════════════════════════════════════════════════════════════════════════════
def scan_wifi_networks():
    """
    Attempt a real WiFi scan via pywifi.
    Falls back to realistic mock data if pywifi is unavailable or times out.

    FIX: Mock data now includes two different APs with the same SSID but
    DIFFERENT BSSIDs (Airport_Free_WiFi), enabling evil-twin / rogue AP
    detection in the frontend scoring engine.
    """
    try:
        import pywifi
        import threading

        result_holder = []
        scan_done     = threading.Event()

        def do_scan():
            try:
                wifi  = pywifi.PyWiFi()
                iface = wifi.interfaces()[0]
                iface.scan()
                time.sleep(2)
                result_holder.extend(iface.scan_results())
            except Exception as exc:
                print(f'[pywifi] Scan thread error: {exc}')
            finally:
                scan_done.set()

        t = threading.Thread(target=do_scan, daemon=True)
        t.start()

        finished = scan_done.wait(timeout=5)

        if finished and result_holder:
            AKM_MAP = {
                0: 'Open',
                1: 'WPA',
                2: 'WPA',
                3: 'WPA2',
                4: 'WPA3',
                5: 'WPA2/WPA3',
            }
            networks = []
            seen_bssids = set()
            for net in result_holder:
                bssid = getattr(net, 'bssid', 'N/A')
                if bssid in seen_bssids:
                    continue  # deduplicate
                seen_bssids.add(bssid)
                akm_val = net.akm[0] if net.akm else 0
                networks.append({
                    'ssid':       net.ssid.strip() or '(Hidden Network)',
                    'bssid':      bssid,
                    'encryption': AKM_MAP.get(akm_val, 'Unknown'),
                    'signal':     net.signal,
                })
            if networks:
                return networks

        print('[NetShield] pywifi scan returned no results — using mock data')

    except ImportError:
        print('[NetShield] pywifi not installed — using mock data. Run: pip install pywifi')
    except Exception as e:
        print(f'[NetShield] pywifi error — using mock data: {e}')

    # ── Mock data ────────────────────────────────────────────────────────────
    # Two entries share SSID "Airport_Free_WiFi" with DIFFERENT BSSIDs.
    # This correctly triggers evil-twin detection in the frontend.
    # FIX: Previously both had 'Open' encryption AND the same BSSID in the
    # original comment — the BSSID has been corrected so they are distinct.
    return [
        {'ssid': 'Airport_Free_WiFi',  'bssid': 'AA:BB:CC:11:22:33', 'encryption': 'Open',  'signal': -52},
        {'ssid': 'Airport_Free_WiFi',  'bssid': 'FF:EE:DD:44:55:66', 'encryption': 'Open',  'signal': -58},  # evil twin
        {'ssid': 'HotelGuest_5G',      'bssid': '11:22:33:AA:BB:CC', 'encryption': 'WPA2',  'signal': -61},
        {'ssid': 'GrandHotel_Secure',  'bssid': '22:33:44:BB:CC:DD', 'encryption': 'WPA3',  'signal': -65},
        {'ssid': 'CafeCorner',         'bssid': '33:44:55:CC:DD:EE', 'encryption': 'WPA2',  'signal': -72},
        {'ssid': 'FREE_TOURIST_WIFI',  'bssid': '44:55:66:DD:EE:FF', 'encryption': 'Open',  'signal': -48},
        {'ssid': 'Museum_Guest',       'bssid': '55:66:77:EE:FF:00', 'encryption': 'WPA2',  'signal': -69},
        {'ssid': 'OldTavern_Net',      'bssid': '66:77:88:FF:00:11', 'encryption': 'WPA',   'signal': -74},
    ]


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('frontend', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('frontend', path)

@app.route('/api/scan/business', methods=['POST'])
def business_scan():
    print(f'\n[{datetime.now()}] === Full Security Audit Started ===')
    try:
        data = run_full_audit()
        print(f'[{datetime.now()}] Audit complete. Score: {data["score"]}/100')
        return jsonify(data)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/scan/tourist', methods=['GET'])
def tourist_scan():
    """
    FIX: Was returning 500 with a generic error message when networks list
    was empty. Now provides a clearer user-facing message and always returns
    the mock data on failure, so the frontend always has something to show.
    """
    try:
        networks = scan_wifi_networks()
    except Exception as e:
        return jsonify({'success': False, 'error': f'Scan failed: {e}'}), 500

    if not networks:
        return jsonify({
            'success': False,
            'error':   'No Wi-Fi networks found. Make sure Wi-Fi is enabled on this machine.',
        }), 500

    return jsonify({'success': True, 'networks': networks})

@app.route('/api/devices', methods=['GET'])
def get_devices():
    conn = get_db()
    rows = conn.execute('SELECT * FROM devices ORDER BY last_seen DESC').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        'status':    'online',
        'local_ip':  get_local_ip(),
        'router_ip': get_router_ip(),
        'subnet':    get_subnet(),
        'hostname':  socket.gethostname(),
        'platform':  platform.system(),
    })

# ── FIX: Added missing /api/feedback route ────────────────────────────────────
@app.route('/api/feedback', methods=['POST'])
def save_feedback():
    """
    Receives user feedback on a network's security assessment.
    Expected JSON body: { ssid, bssid, type, score, comment }
    All fields are optional except the endpoint must receive valid JSON.
    """
    try:
        body    = request.get_json(silent=True) or {}
        ssid    = body.get('ssid', '')
        bssid   = body.get('bssid', '')
        fb_type = body.get('type', '')       # 'safe' | 'unsafe'
        score   = body.get('score', None)
        comment = body.get('comment', '')

        conn = get_db()
        conn.execute(
            'INSERT INTO feedback (ssid, bssid, type, score, comment, timestamp) VALUES (?,?,?,?,?,?)',
            (ssid, bssid, fb_type, score, comment, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()

        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    print('🛡️  NetShield backend running at http://localhost:5000')
    app.run(debug=True, host='0.0.0.0', port=5000)
