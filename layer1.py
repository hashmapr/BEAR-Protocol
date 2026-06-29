from scapy.all import sniff, IP, TCP
from datetime import datetime
import sqlite3
from collections import defaultdict

conn = sqlite3.connect('bear.db')
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS detections
             (timestamp TEXT, src_ip TEXT, dst_port INTEGER, flags TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS ip_reputation
             (ip TEXT PRIMARY KEY, seen_count INTEGER, auto_whitelisted INTEGER)''')

conn.commit()

# Manual whitelist - trusted forever
MANUAL_WHITELIST = [
    '185.199.108.154',  # GitHub CDN
    '140.82.113.22',    # GitHub
    '140.82.114.22',    # GitHub
    '140.82.114.26',    # GitHub
    '140.82.112.25',    # GitHub
    '172.217.24.14',    # Google
    '74.125.130.188',   # Google
    '142.251.43.74',    # Google
    '216.239.38.223',   # Google
    '52.168.117.175',   # Microsoft
    '52.182.143.209',   # Microsoft
    '20.50.201.204',    # Microsoft
    '20.199.39.224',    # Microsoft
    '52.178.17.232',    # Microsoft
    '13.248.151.210',   # AWS
    '35.82.165.80',     # AWS
    '54.189.231.189',   # AWS
    '18.205.95.74',     # AWS
    '208.103.161.1',    # Comcast
    '208.103.161.2',    # Comcast
    '192.168.0.115',    # Local network
    '192.168.0.1',      # Router
    '127.0.0.1',        # Localhost
]

# Auto-whitelist threshold - seen this many times = probably safe
AUTO_WHITELIST_THRESHOLD = 50

def get_ip_count(ip):
    c.execute("SELECT seen_count FROM ip_reputation WHERE ip = ?", (ip,))
    row = c.fetchone()
    return row[0] if row else 0

def increment_ip_count(ip):
    c.execute("""INSERT INTO ip_reputation (ip, seen_count, auto_whitelisted)
                 VALUES (?, 1, 0)
                 ON CONFLICT(ip) DO UPDATE SET seen_count = seen_count + 1""", (ip,))
    conn.commit()

def is_auto_whitelisted(ip):
    c.execute("SELECT auto_whitelisted FROM ip_reputation WHERE ip = ?", (ip,))
    row = c.fetchone()
    return row and row[0] == 1

def auto_whitelist_ip(ip, count):
    c.execute("UPDATE ip_reputation SET auto_whitelisted = 1 WHERE ip = ?", (ip,))
    conn.commit()
    print(f"[BEAR] ✅ AUTO-WHITELISTED — {ip} (seen {count} times, flagged as safe)")

def detect_scan(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src

        if src_ip in MANUAL_WHITELIST:
            return

        if is_auto_whitelisted(src_ip):
            return

        increment_ip_count(src_ip)
        count = get_ip_count(src_ip)

        if count >= AUTO_WHITELIST_THRESHOLD:
            auto_whitelist_ip(src_ip, count)
            return

        timestamp = datetime.now().isoformat()
        dst_port = packet[TCP].dport
        flags = str(packet[TCP].flags)

        print(f"[{timestamp}] ⚠️  UNKNOWN ({count} sightings) — {src_ip} → Port {dst_port} | Flags: {flags}")

        c.execute("INSERT INTO detections VALUES (?,?,?,?)",
                  (timestamp, src_ip, dst_port, flags))
        conn.commit()

print("[BEAR] Layer 1 Active — Listening...")
print(f"[BEAR] Manual whitelist: {len(MANUAL_WHITELIST)} IPs")
print(f"[BEAR] Auto-whitelist threshold: {AUTO_WHITELIST_THRESHOLD} sightings")
print("[BEAR] Learning your network...\n")
sniff(filter="tcp", prn=detect_scan, store=0)