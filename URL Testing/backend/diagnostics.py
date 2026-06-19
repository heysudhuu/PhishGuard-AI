import socket
import ssl
import datetime
import requests
from typing import Dict, Any

def run_domain_diagnostics(domain: str) -> Dict[str, Any]:
    ssl_valid = False
    ssl_issuer = "Unknown / No SSL"
    ssl_expiry = "Unknown"
    location = "Unknown Location"
    isp = "Unknown ISP"
    domain_age_days = 365 * 2 # default to 2 years if lookup fails
    domain_created = "Unknown"
    
    # 1. SSL Socket Handshake
    try:
        context = ssl.create_default_context()
        # Set a short timeout (3 seconds) to prevent hanging
        with socket.create_connection((domain, 443), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_valid = True
                
                # Extract Issuer Common Name
                issuer_tuple = cert.get('issuer', ())
                for item in issuer_tuple:
                    for key, val in item:
                        if key == 'commonName':
                            ssl_issuer = val
                            break
                
                # Extract Expiration Date
                not_after_str = cert.get('notAfter')
                if not_after_str:
                    try:
                        # e.g., 'May  9 12:00:00 2026 GMT'
                        expiry_dt = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                        ssl_expiry = expiry_dt.strftime('%Y-%m-%d')
                    except Exception:
                        ssl_expiry = not_after_str
    except Exception as e:
        print(f"SSL Handshake check failed for {domain}: {e}")
        # If port 443 handshake fails, ssl remains false

    # 2. GeoIP & ISP Lookup (HTTP check to ip-api)
    try:
        resp = requests.get(f"http://ip-api.com/json/{domain}", timeout=3.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                country = data.get("country", "Unknown Country")
                city = data.get("city", "")
                location = f"{city}, {country}" if city else country
                isp = data.get("isp", "Unknown ISP")
    except Exception as e:
        print(f"GeoIP Lookup failed for {domain}: {e}")

    # 3. RDAP Domain Registration Age Lookup
    try:
        # RDAP is the modern RFC replacement for WHOIS, queryable over HTTP/JSON
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=3.0)
        if resp.status_code == 200:
            data = resp.json()
            events = data.get("events", [])
            registration_time = None
            
            # Look for registration event
            for ev in events:
                action = ev.get("eventAction", "")
                if action in ("registration", "creation"):
                    registration_time = ev.get("eventDate")
                    break
            
            if registration_time:
                # Format: '2020-03-24T18:04:12Z' or similar ISO formats
                clean_time = registration_time.split("T")[0]
                domain_created = clean_time
                created_dt = datetime.datetime.strptime(clean_time, "%Y-%m-%d")
                age = datetime.datetime.utcnow() - created_dt
                domain_age_days = max(0, age.days)
    except Exception as e:
        print(f"RDAP/WHOIS Lookup failed for {domain}: {e}")
        # Try a fallback simulation based on domain extensions
        if domain.endswith((".com", ".org", ".net")):
            domain_age_days = 450  # Mock mature domain
            domain_created = "approx. 1.2 years ago (Offline fallback)"
        else:
            domain_age_days = 12   # Mock young domain
            domain_created = "approx. 12 days ago (Offline fallback)"

    # 4. Grading Calculation (0 to 100 points)
    score = 100
    
    # Heuristics adjustments
    if not ssl_valid:
        score -= 30
    if domain_age_days < 30:
        score -= 35
    elif domain_age_days < 180:
        score -= 15
    elif domain_age_days < 365:
        score -= 5
        
    # Check if hosting location is historically higher risk (very simplified heuristic check)
    if "unknown" in location.lower() or "isp" in isp.lower():
        score -= 5

    # Determine grade
    score = max(0, min(100, score))
    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
        
    # Calculate simulated risk score corresponding to grade (0-100 where 100 is high risk)
    risk_score = 100 - score
    
    return {
        "domain": domain,
        "ssl_valid": ssl_valid,
        "ssl_issuer": ssl_issuer,
        "ssl_expiry": ssl_expiry,
        "location": location,
        "isp": isp,
        "domain_age_days": domain_age_days,
        "domain_created": domain_created,
        "grade": grade,
        "risk_score": risk_score
    }
