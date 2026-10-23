"""
Run this script directly to (re)train the AI Behavior Analysis model:

    python ml/train_model.py

It regenerates synthetic "normal" login behaviour and fits a fresh
IsolationForest, overwriting ml/behavior_model.pkl. The Flask app will
also auto-train this model on first run if the file is missing.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from security.ai_engine import train_and_save_model, MODEL_PATH

if __name__ == "__main__":
    train_and_save_model()
    print(f"Model trained and saved to: {os.path.abspath(MODEL_PATH)}")
