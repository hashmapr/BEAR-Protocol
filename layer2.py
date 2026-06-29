import socket
import sqlite3
from datetime import datetime

conn = sqlite3.connect('bear.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS honeypot_sessions
             (timestamp TEXT, src_ip TEXT, src_port INTEGER, data TEXT)''')
conn.commit()

def run_honeypot(port=2222):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    print(f"[BEAR] 🍯 Honeypot active on port {port}")

    while True:
        client, addr = server.accept()
        src_ip, src_port = addr
        timestamp = datetime.now().isoformat()
        print(f"[{timestamp}] 🚨 CONNECTION — {src_ip}:{src_port} touched the honey")

        # Send fake SSH banner
        client.send(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")

        # Collect whatever they send back
        try:
            data = client.recv(1024).decode('utf-8', errors='ignore')
            print(f"[BEAR] Attacker sent: {data}")
            c.execute("INSERT INTO honeypot_sessions VALUES (?,?,?,?)",
                      (timestamp, src_ip, src_port, data))
            conn.commit()
        except:
            pass

        client.close()

run_honeypot()