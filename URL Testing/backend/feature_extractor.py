import re
import urllib.parse
import socket
import ssl
from typing import Dict, Any

SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "update", "bank", "account", "pay", "webscr", "signin", "credential"]
SHORTENING_SERVICES = ["bit.ly", "t.co", "tinyurl", "is.gd", "cli.gs", "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu", "twit.ac", "su.pr", "twurl.nl", "snipurl.com", "short.to", "budurl.com", "ping.fm", "post.ly", "just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us", "doiop.com", "short.ie", "kl.am", "wp.me", "rubyurl.com", "om.ly", "to.ly", "bit.do", "t.co", "lnkd.in", "db.tt", "qr.ae", "adf.ly", "goo.gl", "bitly.com", "cur.lv", "tiny.cc", "ow.ly", "ity.im", "q.gs", "is.gd", "po.st", "bc.vc", "twitthis.com", "u.to", "j.mp", "buzurl.com", "cutt.us", "u.bb", "yourls.org", "x.co", "prettylinkpro.com", "scrnch.me", "filoops.info", "vzturl.com", "qr.net", "1url.com", "tweez.me", "v.gd", "tr.im", "link.zip.net"]

def is_ip_address(domain: str) -> bool:
    # Check if domain matches an IP pattern
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        return True
    # IPv6 check
    if ":" in domain:
        return True
    return False

def check_homograph(domain: str) -> bool:
    # Check if the domain has non-ASCII characters or standard punycode start
    if domain.startswith("xn--"):
        return True
    try:
        domain.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True

def extract_url_features(url: str) -> Dict[str, Any]:
    features = {}
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        # Fallback if invalid URL structure
        return {
            "url_length": len(url),
            "dots_count": url.count("."),
            "subdomain_count": 0,
            "has_at": 1 if "@" in url else 0,
            "is_https": 1 if url.startswith("https") else 0,
            "has_ip": 0,
            "is_shortened": 0,
            "has_suspicious_keyword": 0,
            "is_homograph": 0,
            "special_chars_count": len(re.findall(r"[-_?=&%]", url))
        }

    domain = parsed.netloc.split(":")[0]
    
    # URL Length
    features["url_length"] = len(url)
    
    # Dots Count
    features["dots_count"] = url.count(".")
    
    # Subdomain count
    domain_parts = domain.split(".")
    # Standard domains usually have 2 parts (domain.com) or 3 parts (www.domain.com or domain.co.uk)
    features["subdomain_count"] = max(0, len(domain_parts) - 2)
    
    # Has '@'
    features["has_at"] = 1 if "@" in url else 0
    
    # Is HTTPS
    features["is_https"] = 1 if parsed.scheme.lower() == "https" else 0
    
    # Has IP
    features["has_ip"] = 1 if is_ip_address(domain) else 0
    
    # Is Shortened URL
    features["is_shortened"] = 1 if domain.lower() in SHORTENING_SERVICES else 0
    
    # Has Suspicious Keywords in Path or Query or Host
    has_keyword = 0
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            has_keyword = 1
            break
    features["has_suspicious_keyword"] = has_keyword
    
    # Homograph attack detection
    features["is_homograph"] = 1 if check_homograph(domain) else 0
    
    # Special Characters count (e.g. -, _, ?, =, &, %)
    features["special_chars_count"] = len(re.findall(r"[-_?=&%]", url))
    
    return features

def extract_content_features(html: str) -> Dict[str, Any]:
    # If no html content is provided
    if not html:
        return {
            "has_password_input": 0,
            "brand_impersonation_count": 0,
            "has_hidden_elements": 0
        }
    
    features = {}
    
    # Form with Password Input
    has_password = 1 if "<input" in html.lower() and 'type="password"' in html.lower() else 0
    features["has_password_input"] = has_password
    
    # Brand Impersonation check
    brands = ["paypal", "google", "microsoft", "facebook", "instagram", "amazon", "netflix", "apple", "chase", "bankofamerica"]
    brand_count = 0
    for brand in brands:
        if brand in html.lower():
            brand_count += 1
    features["brand_impersonation_count"] = brand_count
    
    # Hidden Elements that might hide inputs or text
    has_hidden = 0
    if "display:none" in html.replace(" ", "").lower() or "visibility:hidden" in html.replace(" ", "").lower():
        has_hidden = 1
    features["has_hidden_elements"] = has_hidden
    
    return features

# ----------------------------------------------------
# Brand Impersonation Mismatch Logic
# ----------------------------------------------------
OFFICIAL_BRAND_DOMAINS = {
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "google.co.in", "gmail.com", "youtube.com", "blogspot.com", "googleblog.com"],
    "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com", "sharepoint.com", "azure.com", "skype.com"],
    "facebook": ["facebook.com", "fb.com", "messenger.com"],
    "instagram": ["instagram.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.in", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "apple": ["apple.com", "icloud.com"],
    "chase": ["chase.com"],
    "bankofamerica": ["bankofamerica.com", "bofa.com"]
}

def check_brand_mismatch(url: str, html: str = "") -> bool:
    """
    Checks if a brand name is used in the URL or HTML but the host domain does not
    match the official domains of that brand.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.split(":")[0].lower()
    except Exception:
        return False
        
    url_lower = url.lower()
    html_lower = html.lower() if html else ""
    
    for brand, official_domains in OFFICIAL_BRAND_DOMAINS.items():
        # Check if brand name is mentioned in URL or HTML
        brand_mentioned_in_url = brand in url_lower
        brand_mentioned_in_html = brand in html_lower
        
        if brand_mentioned_in_url or brand_mentioned_in_html:
            # Check if domain matches any of the official domains
            is_official = False
            for off_dom in official_domains:
                if domain == off_dom or domain.endswith("." + off_dom):
                    is_official = True
                    break
            
            if not is_official:
                return True
    return False

