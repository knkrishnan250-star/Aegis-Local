# 🛡️ Aegis-Local: AI Behavioral IDS
![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![AI](https://img.shields.io/badge/AI-Ollama%20Llama3.2-orange.svg)
![Security](https://img.shields.io/badge/Security-Passive%20IDS-red.svg)

### 🚀 The Concept
Aegis-Local is a private "Digital Immune System" for your PC. It uses a **Local LLM** to analyze process intent. If an app starts behaving like malware (e.g., an unknown app trying to access the network), the AI flags it in a local audit log.

### 📊 System Flow


### 🛠️ How to Run
1. **Local AI:** Install [Ollama](https://ollama.com) and run `ollama pull llama3.2:1b`.
2. **Install Deps:** `pip install -r requirements.txt`.
3. **Run Guard:** `python aegis_observer.py`.
4. **View Dashboard:** `streamlit run aegis_dashboard.py`.
