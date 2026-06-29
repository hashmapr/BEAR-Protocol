import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict

DB_PATH = 'bear.db'

# Session timeout - packets from same IP within this window = one session
SESSION_TIMEOUT_SECONDS = 60

# Suspicious flag combinations
SCAN_FLAGS = ['S', 'SF', 'SFUP']

# Known safe port ranges
COMMON_PORTS = {
    80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
    25: 'SMTP', 53: 'DNS', 3306: 'MySQL', 5432: 'PostgreSQL',
    8080: 'HTTP-Alt', 3389: 'RDP', 445: 'SMB', 139: 'NetBIOS'
}

def load_detections():
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("""
        SELECT timestamp, src_ip, dst_port, flags 
        FROM detections 
        ORDER BY src_ip, timestamp
    """).fetchall()
    conn.close()
    return rows

def group_into_sessions(detections):
    sessions = defaultdict(list)
    
    for timestamp, src_ip, dst_port, flags in detections:
        sessions[src_ip].append({
            'timestamp': datetime.fromisoformat(timestamp),
            'dst_port': dst_port,
            'flags': flags
        })
    
    # Split into time-bounded sessions
    bounded_sessions = []
    for src_ip, packets in sessions.items():
        packets.sort(key=lambda x: x['timestamp'])
        
        current_session = [packets[0]]
        
        for packet in packets[1:]:
            time_diff = (packet['timestamp'] - current_session[-1]['timestamp']).seconds
            if time_diff > SESSION_TIMEOUT_SECONDS:
                bounded_sessions.append({
                    'src_ip': src_ip,
                    'packets': current_session
                })
                current_session = [packet]
            else:
                current_session.append(packet)
        
        bounded_sessions.append({
            'src_ip': src_ip,
            'packets': current_session
        })
    
    return bounded_sessions

def score_session(session):
    src_ip = session['src_ip']
    packets = session['packets']
    ports_hit = list(set(p['dst_port'] for p in packets))
    flags_seen = list(set(p['flags'] for p in packets))
    
    score = 0
    reasons = []
    
    # Port scan detection
    if len(ports_hit) > 10:
        score += 40
        reasons.append(f"Port scan: {len(ports_hit)} unique ports probed")
    elif len(ports_hit) > 5:
        score += 20
        reasons.append(f"Mild port scan: {len(ports_hit)} ports probed")
    
    # Suspicious flag detection
    for flag in SCAN_FLAGS:
        if flag in flags_seen:
            score += 30
            reasons.append(f"Suspicious flag: {flag}")
            break
    
    # Sequential port scanning
    sorted_ports = sorted(ports_hit)
    sequential = 0
    for i in range(1, len(sorted_ports)):
        if sorted_ports[i] - sorted_ports[i-1] == 1:
            sequential += 1
    if sequential > 5:
        score += 25
        reasons.append(f"Sequential port scan detected: {sequential} consecutive ports")
    
    # High packet volume
    if len(packets) > 100:
        score += 15
        reasons.append(f"High volume: {len(packets)} packets")
    
    # Targeting sensitive ports
    sensitive_ports = [22, 3306, 5432, 3389, 445, 139]
    hit_sensitive = [p for p in ports_hit if p in sensitive_ports]
    if hit_sensitive:
        score += 20
        reasons.append(f"Sensitive ports targeted: {[COMMON_PORTS.get(p, p) for p in hit_sensitive]}")
    
    # Cap at 100
    score = min(score, 100)
    
    # Threat level
    if score >= 70:
        threat = "🔴 CRITICAL"
    elif score >= 40:
        threat = "🟡 SUSPICIOUS"
    elif score >= 20:
        threat = "🟠 ELEVATED"
    else:
        threat = "🟢 NORMAL"
    
    duration = (packets[-1]['timestamp'] - packets[0]['timestamp']).seconds
    
    return {
        'src_ip': src_ip,
        'threat_level': threat,
        'score': score,
        'reasons': reasons,
        'ports_hit': ports_hit,
        'packet_count': len(packets),
        'duration_seconds': duration,
        'start_time': packets[0]['timestamp'].isoformat(),
        'flags_seen': flags_seen
    }

def save_sessions(analyzed_sessions):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS analyzed_sessions
                 (timestamp TEXT, src_ip TEXT, threat_level TEXT, 
                  score INTEGER, reasons TEXT, ports_hit TEXT,
                  packet_count INTEGER, duration_seconds INTEGER)''')
    
    for s in analyzed_sessions:
        conn.execute("""
            INSERT INTO analyzed_sessions VALUES (?,?,?,?,?,?,?,?)
        """, (
            s['start_time'],
            s['src_ip'],
            s['threat_level'],
            s['score'],
            ' | '.join(s['reasons']),
            str(s['ports_hit']),
            s['packet_count'],
            s['duration_seconds']
        ))
    
    conn.commit()
    conn.close()

def print_report(analyzed_sessions):
    print("="*60)
    print("🐻 BEAR Protocol — Session Intelligence Report")
    print("="*60)
    
    # Sort by score
    sorted_sessions = sorted(analyzed_sessions, key=lambda x: x['score'], reverse=True)
    
    total = len(sorted_sessions)
    critical = len([s for s in sorted_sessions if s['score'] >= 70])
    suspicious = len([s for s in sorted_sessions if 40 <= s['score'] < 70])
    normal = len([s for s in sorted_sessions if s['score'] < 20])
    
    print(f"\n📊 OVERVIEW")
    print(f"   Total sessions analyzed: {total}")
    print(f"   🔴 Critical:    {critical}")
    print(f"   🟡 Suspicious:  {suspicious}")
    print(f"   🟢 Normal:      {normal}")
    
    # Top threats
    threats = [s for s in sorted_sessions if s['score'] >= 40]
    
    if threats:
        print(f"\n🚨 TOP THREATS")
        print("-"*60)
        for s in threats[:10]:
            print(f"\n  {s['threat_level']} | Score: {s['score']}/100")
            print(f"  IP: {s['src_ip']}")
            print(f"  Time: {s['start_time']}")
            print(f"  Packets: {s['packet_count']} over {s['duration_seconds']}s")
            print(f"  Ports targeted: {len(s['ports_hit'])}")
            if s['reasons']:
                print(f"  Why flagged:")
                for r in s['reasons']:
                    print(f"    → {r}")
    else:
        print("\n✅ No significant threats detected in this session window.")
    
    print("\n" + "="*60)
    print("Sessions saved to bear.db → analyzed_sessions table")
    print("Ready for Layer 4 LLM interpretation.")

# Run
print("[BEAR] Loading detections from database...")
detections = load_detections()
print(f"[BEAR] Loaded {len(detections)} raw packets")

print("[BEAR] Grouping into sessions...")
sessions = group_into_sessions(detections)
print(f"[BEAR] Found {len(sessions)} distinct sessions")

print("[BEAR] Analyzing and scoring...")
analyzed = [score_session(s) for s in sessions]

print("[BEAR] Saving to database...")
save_sessions(analyzed)

print_report(analyzed)