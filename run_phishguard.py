"""
PhishGuard - Launcher Script
Launches the full unified web application on http://127.0.0.1:8000.
"""

import sys
import os
import webbrowser
import uvicorn

# Ensure the root directory is on the python search path
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.app.ml.model_trainer import train_and_save_models

def main():
    print("=" * 70)
    print("          PHISHGUARD - AI-POWERED CYBER DEFENSE SYSTEM          ")
    print("      Phishing URL & Email Threat Detection Platform v1.0       ")
    print("=" * 70)

    # 1. Ensure ML models exist
    print("[1/3] Verifying Machine Learning models (Random Forest & NLP)...")
    train_and_save_models(force_retrain=False)
    print("      ✓ ML models verified and ready for inference.")

    # 2. Server configuration
    host = "127.0.0.1"
    port = 8000
    url = f"http://{host}:{port}/"
    print(f"[2/3] Initializing FastAPI Core & Serving React Cyber UI...")
    print(f"      Access PhishGuard at: {url}")
    print(f"[3/3] Launching web server. Press Ctrl+C to terminate.")
    print("=" * 70)

    # Automatically open browser after server start (in non-headless environment)
    try:
        webbrowser.open(url)
    except Exception:
        pass

    # Run Uvicorn
    uvicorn.run("backend.app.main:app", host=host, port=port, reload=False)

if __name__ == "__main__":
    main()

