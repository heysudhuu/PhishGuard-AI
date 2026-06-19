from typing import Dict, Any

def calculate_risk_score(features: Dict[str, Any], reputation: Dict[str, Any], ml_prob: float) -> Dict[str, Any]:
    """
    Combines ML, Reputation, and Heuristics to compute a final risk score.
    Returns:
        dict: {
            "score": int (0-100),
            "level": str ("safe" | "suspicious" | "dangerous"),
            "ml_score": int,
            "rep_score": int,
            "heuristics_score": int
        }
    """
    # 1. Whitelist bypass
    if reputation.get("is_whitelisted", False):
        return {
            "score": 0,
            "level": "safe",
            "ml_score": 0,
            "rep_score": 0,
            "heuristics_score": 0
        }
        
    # 1.5 Blacklist force match
    if reputation.get("is_blacklisted", False):
        return {
            "score": 100,
            "level": "dangerous",
            "ml_score": 100,
            "rep_score": 100,
            "heuristics_score": 100
        }
        
    # 2. ML Score
    ml_score = int(round(ml_prob * 100))
    
    # 3. Reputation Score
    rep_score = 0
    vt = reputation.get("virustotal", {})
    gsb = reputation.get("safe_browsing", {})
    
    if reputation.get("openphish_match", False):
        rep_score = 100
    elif gsb.get("is_flagged", False):
        rep_score = 100
    elif vt.get("malicious_count", 0) >= 2:
        rep_score = 95
    elif vt.get("malicious_count", 0) > 0 or vt.get("suspicious_count", 0) > 0:
        rep_score = 70
        
    # 4. Heuristics Score
    h_score = 0
    if features.get("has_ip", 0): 
        h_score += 35
    if features.get("is_homograph", 0): 
        h_score += 30
    if features.get("is_shortened", 0): 
        h_score += 15
    if features.get("has_suspicious_keyword", 0): 
        h_score += 20
    if features.get("has_password_input", 0) and features.get("brand_impersonation_count", 0) > 0: 
        h_score += 40
    if features.get("brand_mismatch", 0):
        h_score += 40
    if not features.get("is_https", 0): 
        h_score += 15
    if features.get("subdomain_count", 0) >= 3: 
        h_score += 15
        
    heuristics_score = min(100, h_score)
    
    # 5. Combined Score Calculation
    if rep_score >= 95:
        # Known threat: highly dangerous
        final_score = max(rep_score, ml_score)
    elif rep_score > 0:
        # Suspicious threat feed match: heavy weight
        final_score = 0.7 * rep_score + 0.3 * max(ml_score, heuristics_score)
    else:
        # Standard scoring: half ML, half heuristics
        final_score = 0.5 * ml_score + 0.5 * heuristics_score
        
    # Clamp and round
    final_score = max(0, min(100, int(round(final_score))))
    
    # Classify Risk Level
    if final_score <= 30:
        level = "safe"
    elif final_score <= 65:
        level = "suspicious"
    else:
        level = "dangerous"
        
    return {
        "score": final_score,
        "level": level,
        "ml_score": ml_score,
        "rep_score": rep_score,
        "heuristics_score": heuristics_score
    }
