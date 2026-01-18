import psutil
import ollama
import time
import datetime

# --- CONFIGURATION ---
LOG_FILE = "security_alerts.log"
SAFE_PROCESSES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "python.exe", 
    "code.exe", "discord.exe", "teams.exe", "zoom.exe", "ollama.exe"
}

def log_event(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def get_ai_analysis(proc_data):
    # Structured 2026 Prompting for consistent AI results
    prompt = f"""
    You are a cybersecurity analyst.
    Analyze this process behavior on a normal personal laptop.

    Process: {proc_data['name']}
    Connections: {proc_data['net']}

    Reply strictly in this format:
    STATUS: [SAFE or SUSPICIOUS]
    REASON: [one short sentence]
    """
    try:
        response = ollama.chat(model='llama3.2:1b', messages=[{'role': 'user', 'content': prompt}])
        return response['message']['content'].strip()
    except:
        return "STATUS: ERROR | REASON: AI offline"

def main():
    print("--- Aegis Observer Active (Passive Mode) ---")
    seen_pids = set()

    try:
        while True:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']

                    if pid not in seen_pids:
                        # 1. Apply Local Allowlist
                        if name.lower() in SAFE_PROCESSES:
                            seen_pids.add(pid)
                            continue

                        connections = proc.net_connections()
                        if connections:
                            seen_pids.add(pid)
                            proc_data = {
                                "name": name,
                                "net": [f"{c.laddr.ip}:{c.laddr.port}" for c in connections]
                            }
                            
                            analysis = get_ai_analysis(proc_data)
                            log_event(f"PROCESS: {name} | ANALYSIS: {analysis}")
                            print(f"[Captured] {name} -> AI Analysis logged.")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            time.sleep(2) 
    except KeyboardInterrupt:
        print("\n[-] Aegis Observer stopped.")

if __name__ == "__main__":
    main()
