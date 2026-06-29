import socket
import sqlite3
import threading
from datetime import datetime

DB_PATH = 'bear.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS honeypot_sessions
                 (timestamp TEXT, service TEXT, src_ip TEXT, src_port INTEGER, data TEXT)''')
    conn.commit()
    conn.close()

def log_session(service, src_ip, src_port, data):
    timestamp = datetime.now().isoformat()
    print(f"[{timestamp}] 🚨 {service} HIT — {src_ip}:{src_port}")
    if data:
        print(f"[BEAR] Attacker sent: {repr(data)}")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT INTO honeypot_sessions VALUES (?,?,?,?,?)",
                 (timestamp, service, src_ip, src_port, data))
    conn.commit()
    conn.close()

def handle_client(client, addr, service, banner, prompt=None):
    src_ip, src_port = addr
    try:
        client.send(banner)
        if prompt:
            client.send(prompt)
        data = client.recv(1024).decode('utf-8', errors='ignore').strip()
        log_session(service, src_ip, src_port, data)
        if service == "SSH":
            client.send(b"Permission denied (publickey,password).\r\n")
        elif service == "FTP":
            client.send(b"530 Login incorrect.\r\n")
        elif service == "HTTP":
            client.send(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Admin\"\r\n\r\n")
        elif service == "SMTP":
            client.send(b"535 5.7.8 Authentication credentials invalid\r\n")
        elif service == "TELNET":
            client.send(b"Login incorrect\r\n")
    except Exception as e:
        log_session(service, src_ip, src_port, "")
    finally:
        client.close()

def run_honeypot(port, service, banner, prompt=None):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"[BEAR] 🍯 {service} honeypot active on port {port}")

    while True:
        try:
            client, addr = server.accept()
            thread = threading.Thread(
                target=handle_client,
                args=(client, addr, service, banner, prompt)
            )
            thread.daemon = True
            thread.start()
        except:
            pass

SERVICES = [
    {
        'port': 2222,
        'service': 'SSH',
        'banner': b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
        'prompt': b"root@ubuntu:~$ "
    },
    {
        'port': 8080,
        'service': 'HTTP',
        'banner': b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Admin Panel</h1></body></html>",
        'prompt': None
    },
    {
        'port': 2121,
        'service': 'FTP',
        'banner': b"220 FTP Server ready.\r\n",
        'prompt': b"Username: "
    },
    {
        'port': 2525,
        'service': 'SMTP',
        'banner': b"220 mail.company.com ESMTP Postfix\r\n",
        'prompt': None
    },
    {
        'port': 2323,
        'service': 'TELNET',
        'banner': b"\r\nUbuntu 22.04 LTS\r\n",
        'prompt': b"login: "
    },
]

init_db()
print("[BEAR] 🐻 Layer 2 — Multi-Service Honeypot Network")
print("="*50)

threads = []
for svc in SERVICES:
    t = threading.Thread(
        target=run_honeypot,
        args=(svc['port'], svc['service'], svc['banner'], svc.get('prompt'))
    )
    t.daemon = True
    t.start()
    threads.append(t)

print("\n[BEAR] All honeypots armed. Waiting for visitors...\n")

try:
    for t in threads:
        t.join()
except KeyboardInterrupt:
    print("\n[BEAR] Honeypots offline.")