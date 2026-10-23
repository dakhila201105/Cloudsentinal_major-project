"""
AI Behavior Analysis Engine
----------------------------
Trains (or loads) an IsolationForest anomaly-detection model on synthetic
"normal" login behaviour and scores incoming login attempts for anomaly.

Features used per login event:
    [hour_of_day, is_known_device (0/1), is_known_location (0/1),
     recent_failed_attempts, requests_last_minute]
"""

import os
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "ml", "behavior_model.pkl")


def _generate_synthetic_normal_data(n=2000, seed=42):
    """Simulate typical, everyday legitimate login behaviour."""
    rng = np.random.default_rng(seed)
    hours = rng.normal(loc=14, scale=3.5, size=n).clip(0, 23)          # office hours bias
    known_device = rng.choice([1, 1, 1, 1, 0], size=n)                 # mostly known devices
    known_location = rng.choice([1, 1, 1, 1, 0], size=n)
    failed_attempts = rng.poisson(0.2, size=n).clip(0, 5)
    requests_per_min = rng.normal(loc=3, scale=1.5, size=n).clip(0, 20)
    return np.column_stack([hours, known_device, known_location, failed_attempts, requests_per_min])


def train_and_save_model():
    data = _generate_synthetic_normal_data()
    model = IsolationForest(
        n_estimators=200,
        contamination=0.08,
        random_state=42,
    )
    model.fit(data)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    return model


def load_model():
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    return train_and_save_model()


_model = None


def get_model():
    global _model
    if _model is None:
        _model = load_model()
    return _model


def anomaly_score(hour, known_device, known_location, failed_attempts, requests_per_min):
    """
    Returns a normalized anomaly score in [0, 1] where 1 = highly anomalous.
    Uses IsolationForest's decision_function: lower (more negative) = more anomalous.
    """
    model = get_model()
    features = np.array([[hour, known_device, known_location, failed_attempts, requests_per_min]])
    raw = model.decision_function(features)[0]   # roughly in [-0.5, 0.5]
    # invert & squash into [0, 1]
    score = 1 / (1 + np.exp(8 * raw))  # sigmoid; raw<0 (anomalous) -> score near 1
    return float(np.clip(score, 0, 1))
