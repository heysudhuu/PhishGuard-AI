from typing import Dict, Any, List

def generate_explanations(features: Dict[str, Any], reputation: Dict[str, Any], ml_prob: float) -> List[str]:
    explanations = []
    
    # 1. Reputation Checks (Highest Priority)
    if reputation.get("is_whitelisted", False):
        return ["This domain is verified on our global whitelist of high-traffic, trusted sites."]
        
    if reputation.get("is_blacklisted", False):
        return ["This domain has been explicitly blocked by your custom domain blacklist policies."]
        
    if reputation.get("openphish_match", False):
        explanations.append("This URL is actively blacklisted in OpenPhish's live threat intelligence feed.")
        
    vt = reputation.get("virustotal", {})
    if vt.get("is_flagged", False):
        malicious = vt.get("malicious_count", 0)
        suspicious = vt.get("suspicious_count", 0)
        total = vt.get("total_scanners", 0)
        explanations.append(f"Flagged as malicious/suspicious by {malicious + suspicious} security engines on VirusTotal.")
        
    gsb = reputation.get("safe_browsing", {})
    if gsb.get("is_flagged", False):
        matches = gsb.get("matches", [])
        threat_str = ", ".join([m.lower().replace("_", " ") for m in matches])
        explanations.append(f"Google Safe Browsing flagged this site for: {threat_str}.")

    # 2. Key Content/Brand Checks
    if features.get("brand_mismatch", 0) == 1:
        explanations.append("Brand Impersonation Warning: The page mentions or targets a known brand (e.g. PayPal, Google, Microsoft, Amazon) but is hosted on an unverified domain.")

    if features.get("has_password_input", 0) == 1:
        if features.get("brand_impersonation_count", 0) > 0:
            explanations.append("High Risk: The page requests credentials (password input) and references known brands, but the domain does not match.")
        else:
            explanations.append("Note: This page contains a login form requesting password credentials.")

    # 3. URL Heuristics
    if features.get("has_ip", 0) == 1:
        explanations.append("The website uses a raw IP address instead of a domain name, which is highly suspicious.")
        
    if features.get("is_homograph", 0) == 1:
        explanations.append("Potential Homograph Attack: The domain name contains international characters (IDN) that mimic letters in legitimate brand names.")

    if features.get("is_shortened", 0) == 1:
        explanations.append("The website uses a URL shortening service to hide the final destination address.")

    if features.get("has_suspicious_keyword", 0) == 1:
        explanations.append("The URL contains deceptive words like 'login', 'secure', or 'verify' indicating brand-spoofing behavior.")

    if features.get("subdomain_count", 0) >= 3:
        explanations.append(f"The URL contains an excessive number of subdomains ({features['subdomain_count']}), often used to impersonate brand domains.")

    if features.get("url_length", 0) > 85:
        explanations.append(f"The URL length is unusually long ({features['url_length']} characters), which can be used to hide suspicious parameters.")

    if features.get("has_at", 0) == 1:
        explanations.append("The URL contains an '@' symbol. The browser may treat preceding characters as username details, masking the real domain.")

    if features.get("is_https", 0) == 0:
        explanations.append("The connection to this site is insecure (HTTP). Legitimate login and payment pages always require secure (HTTPS) connections.")

    if features.get("has_hidden_elements", 0) == 1:
        explanations.append("The page source contains hidden visual styles, which phishing kits often use to hide malicious fields or brand text from crawlers.")

    # If no specific warning was generated but ML probability is moderate to high
    if not explanations:
        if ml_prob > 0.6:
            explanations.append("The ML model detected structural patterns in the URL and page content consistent with phishing kits.")
        else:
            explanations.append("No significant structural anomalies or blacklists matched this URL.")

    return explanations
