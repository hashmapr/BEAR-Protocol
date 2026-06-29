import socket
import time
import sqlite3

def test_service(name, host, port, send_data=None, expected=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))
        banner = s.recv(1024).decode('utf-8', errors='ignore')
        
        if send_data:
            s.send(send_data)
            time.sleep(0.5)
            response = s.recv(1024).decode('utf-8', errors='ignore')
        else:
            response = ""
        
        s.close()
        
        if expected and expected not in banner + response:
            print(f"❌ {name} (port {port}) — Connected but unexpected response")
            print(f"   Got: {repr(banner[:100])}")
            return False
        
        print(f"✅ {name} (port {port}) — ALIVE")
        print(f"   Banner: {repr(banner.strip()[:80])}")
        if response:
            print(f"   Response: {repr(response.strip()[:80])}")
        return True
        
    except ConnectionRefusedError:
        print(f"❌ {name} (port {port}) — NOT RUNNING")
        return False
    except Exception as e:
        print(f"❌ {name} (port {port}) — ERROR: {e}")
        return False

def test_db():
    try:
        conn = sqlite3.connect('bear.db')
        sessions = conn.execute("SELECT COUNT(*) FROM honeypot_sessions").fetchone()[0]
        detections = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        whitelisted = conn.execute("SELECT COUNT(*) FROM ip_reputation WHERE auto_whitelisted=1").fetchone()[0]
        conn.close()
        print(f"✅ Database — HEALTHY")
        print(f"   Honeypot sessions logged: {sessions}")
        print(f"   Layer 1 detections logged: {detections}")
        print(f"   Auto-whitelisted IPs: {whitelisted}")
        return True
    except Exception as e:
        print(f"❌ Database — ERROR: {e}")
        return False

def test_http():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(('localhost', 8080))
        s.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        response = s.recv(1024).decode('utf-8', errors='ignore')
        s.close()
        if 'Admin Panel' in response or 'HTTP' in response:
            print(f"✅ HTTP (port 8080) — ALIVE")
            print(f"   Response: {repr(response.strip()[:80])}")
            return True
        print(f"❌ HTTP (port 8080) — Unexpected response")
        return False
    except ConnectionRefusedError:
        print(f"❌ HTTP (port 8080) — NOT RUNNING")
        return False
    except Exception as e:
        print(f"❌ HTTP (port 8080) — ERROR: {e}")
        return False

print("="*50)
print("🐻 BEAR Protocol — System Test")
print("="*50)

print("\n[1] HONEYPOT SERVICES")
print("-"*30)
results = []
results.append(test_service("SSH",    "localhost", 2222, b"test_user\n", "SSH"))
results.append(test_http())
results.append(test_service("FTP",    "localhost", 2121, b"testuser\n", "220"))
results.append(test_service("SMTP",   "localhost", 2525, b"EHLO test\r\n", "220"))
results.append(test_service("TELNET", "localhost", 2323, b"admin\n", "Ubuntu"))

print("\n[2] DATABASE")
print("-"*30)
results.append(test_db())

print("\n[3] SUMMARY")
print("-"*30)
passed = sum(results)
total = len(results)
print(f"{'✅' if passed == total else '⚠️ '} {passed}/{total} checks passed")

if passed == total:
    print("\n🐻 BEAR Protocol fully operational.")
else:
    print("\n⚠️  Some services are down. Is layer2.py running?")