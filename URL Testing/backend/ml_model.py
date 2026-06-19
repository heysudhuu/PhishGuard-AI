import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List

# Get current path
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BACKEND_DIR, "model.joblib")
FEATURES_PATH = os.path.join(BACKEND_DIR, "features.joblib")

_model = None
_feature_cols = None

def load_model():
    global _model, _feature_cols
    
    if _model is not None:
        return _model, _feature_cols
    
    # Check if files exist, if not, train model
    if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURES_PATH):
        print("Model or feature metadata not found. Training model now...")
        try:
            from backend.train_model import train_model
            train_model()
        except ImportError:
            # If loaded as main or different module path
            from train_model import train_model
            train_model()
            
    # Load model and features
    _model = joblib.load(MODEL_PATH)
    _feature_cols = joblib.load(FEATURES_PATH)
    return _model, _feature_cols

def predict_phishing_probability(features: Dict[str, Any]) -> float:
    """
    Predicts the probability of the URL being a phishing site.
    Returns value between 0.0 and 1.0.
    """
    try:
        model, feature_cols = load_model()
        
        # Prepare feature vector as a Pandas DataFrame to maintain feature names
        row_dict = {}
        for col in feature_cols:
            val = features.get(col, 0)
            # Ensure boolean conversion to int
            if isinstance(val, bool):
                val = 1 if val else 0
            row_dict[col] = [val]
            
        x_input = pd.DataFrame(row_dict)
        
        # Get probabilities
        # classes are typically [0 (benign), 1 (phishing)]
        probs = model.predict_proba(x_input)[0]
        
        # Return probability of class 1 (phishing)
        return float(probs[1])
    except Exception as e:
        print(f"Error during ML prediction: {e}")
        # Return a heuristic-based probability as backup
        return run_heuristic_backup(features)

def run_heuristic_backup(features: Dict[str, Any]) -> float:
    """
    Fallback simple heuristic classifier if ML engine fails.
    """
    score = 0.0
    if features.get("has_suspicious_keyword", 0):
        score += 0.35
    if features.get("has_ip", 0):
        score += 0.25
    if features.get("is_shortened", 0):
        score += 0.15
    if features.get("subdomain_count", 0) >= 3:
        score += 0.15
    if features.get("is_homograph", 0):
        score += 0.20
    if not features.get("is_https", 0):
        score += 0.15
    if features.get("has_password_input", 0) and features.get("brand_impersonation_count", 0) > 0:
        score += 0.25
        
    return min(1.0, score)

def get_feature_importances() -> Dict[str, float]:
    """
    Returns a dict mapping feature names to their importances.
    """
    try:
        model, feature_cols = load_model()
        importances = model.feature_importances_
        return {col: float(imp) for col, imp in zip(feature_cols, importances)}
    except Exception:
        return {}
