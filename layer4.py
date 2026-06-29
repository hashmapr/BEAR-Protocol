import sqlite3
import requests
import json

DB_PATH = 'bear.db'
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2"

def load_threat_sessions():
    conn = sqlite3.connect(DB_PATH)
    sessions = conn.execute("""
        SELECT src_ip, threat_level, score, reasons, 
               ports_hit, packet_count, duration_seconds, timestamp
        FROM analyzed_sessions
        WHERE score >= 40
        ORDER BY score DESC
    """).fetchall()
    conn.close()
    return sessions

def build_prompt(session):
    src_ip, threat_level, score, reasons, ports_hit, packet_count, duration, timestamp = session
    
    return f"""You are a cybersecurity analyst for BEAR Protocol, an autonomous deception network.
Analyze this network threat session and provide a concise intelligence report.

SESSION DATA:
- Source IP: {src_ip}
- Threat Score: {score}/100
- Threat Level: {threat_level}
- Time: {timestamp}
- Packets sent: {packet_count}
- Duration: {duration} seconds
- Ports targeted: {ports_hit}
- Why flagged: {reasons}

Provide a SHORT intelligence report with exactly these sections:
1. ASSESSMENT (1 sentence - what is this?)
2. TECHNIQUE (1 sentence - what attack technique?)
3. INTENT (1 sentence - what were they looking for?)
4. RECOMMENDATION (1 sentence - what should we do?)

Be direct and technical. No fluff."""

def query_ollama(prompt):
    try:
        response = requests.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=30)
        
        if response.status_code == 200:
            return response.json().get('response', 'No response')
        return f"Error: {response.status_code}"
    except requests.exceptions.ConnectionError:
        return "Error: Ollama not running. Start with: ollama serve"
    except Exception as e:
        return f"Error: {e}"

def save_intelligence(src_ip, score, analysis):
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''CREATE TABLE IF NOT EXISTS threat_intelligence
                 (timestamp TEXT, src_ip TEXT, score INTEGER, analysis TEXT)''')
    conn.execute("INSERT INTO threat_intelligence VALUES (datetime('now'), ?, ?, ?)",
                 (src_ip, score, analysis))
    conn.commit()
    conn.close()

# Run Layer 4
print("="*60)
print("🐻 BEAR Protocol — Layer 4: Threat Intelligence")
print(f"   Model: {MODEL}")
print("="*60)

sessions = load_threat_sessions()

if not sessions:
    print("No threat sessions found. Run session_analyzer.py first.")
    exit()

print(f"\n[BEAR] Analyzing {len(sessions)} threat sessions with {MODEL}...\n")

for i, session in enumerate(sessions):
    src_ip = session[0]
    score = session[2]
    
    print(f"{'='*60}")
    print(f"[{i+1}/{len(sessions)}] Analyzing {src_ip} (Score: {score}/100)")
    print(f"{'='*60}")
    
    prompt = build_prompt(session)
    print("[BEAR] Querying LLM...", end='', flush=True)
    analysis = query_ollama(prompt)
    print(" done.")
    
    print(f"\n{analysis}")
    
    save_intelligence(src_ip, score, analysis)
    print(f"\n[BEAR] Intelligence saved to database.")

print("\n" + "="*60)
print("🐻 Layer 4 complete. Threat intelligence logged.")
print("="*60)