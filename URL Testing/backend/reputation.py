import requests
import os
import urllib.parse
import threading
from typing import Dict, Any, List, Optional

# Simple local whitelist of major domains to prevent false positives
WHITELIST = [
    "google.com", "www.google.com", "youtube.com", "www.youtube.com",
    "facebook.com", "www.facebook.com", "microsoft.com", "www.microsoft.com",
    "apple.com", "www.apple.com", "amazon.com", "www.amazon.com",
    "netflix.com", "www.netflix.com", "linkedin.com", "www.linkedin.com",
    "github.com", "www.github.com", "twitter.com", "www.twitter.com",
    "wikipedia.org", "www.wikipedia.org", "yahoo.com", "www.yahoo.com",
    "reddit.com", "www.reddit.com", "instagram.com", "www.instagram.com"
]

# Simple local blacklist of test phishing URLs
LOCAL_BLACKLIST = [
    "paypal-security-login-update.xyz",
    "chase-verify-identity-confirm.net",
    "bankofamerica-login-authorization-portal.com",
    "secure-login-microsoft-outlook.xyz",
    "instagram-login-verification-badge.cc"
]

class ReputationEngine:
    def __init__(self):
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.gsb_api_key = os.getenv("SAFE_BROWSING_API_KEY", "")
        self.openphish_urls = set()
        self.load_openphish_feed()
        self.cache = {}
        self.cache_lock = threading.Lock()
        
    def get_cached_result(self, url: str) -> Optional[Dict[str, Any]]:
        with self.cache_lock:
            return self.cache.get(url)
            
    def cache_result(self, url: str, result: Dict[str, Any]):
        with self.cache_lock:
            if len(self.cache) >= 1000:
                try:
                    self.cache.pop(next(iter(self.cache)))
                except StopIteration:
                    pass
            self.cache[url] = result
        
    def load_openphish_feed(self):
        """
        Attempts to fetch OpenPhish's free community feed and cache it.
        """
        try:
            # OpenPhish free community feed is a list of active phishing URLs
            response = requests.get("https://openphish.com/feed.txt", timeout=3)
            if response.status_code == 200:
                self.openphish_urls = set(response.text.splitlines())
                print(f"Loaded {len(self.openphish_urls)} active phishing URLs from OpenPhish.")
            else:
                print("OpenPhish feed request returned status:", response.status_code)
        except Exception as e:
            print("Could not load OpenPhish live feed, using offline list.", e)
            
    def check_whitelist(self, domain: str, db=None) -> bool:
        domain_lower = domain.lower()
        if domain_lower in WHITELIST:
            return True
            
        if db is not None:
            try:
                import backend.models as models
                # Direct check
                exists = db.query(models.Whitelist).filter(models.Whitelist.domain == domain_lower).first()
                if exists:
                    return True
                
                # Check parent domains (wildcard behavior)
                parts = domain_lower.split(".")
                if len(parts) >= 3:
                    for i in range(1, len(parts) - 1):
                        parent = ".".join(parts[i:])
                        exists_parent = db.query(models.Whitelist).filter(models.Whitelist.domain == parent).first()
                        if exists_parent:
                            return True
            except Exception as e:
                print(f"Error checking database whitelist: {e}")
                
        return False
        
    def check_blacklist(self, domain: str, db=None) -> bool:
        domain_lower = domain.lower()
        if db is not None:
            try:
                import backend.models as models
                # Direct check
                exists = db.query(models.Blacklist).filter(models.Blacklist.domain == domain_lower).first()
                if exists:
                    return True
                
                # Check parent domains (wildcard behavior)
                parts = domain_lower.split(".")
                if len(parts) >= 3:
                    for i in range(1, len(parts) - 1):
                        parent = ".".join(parts[i:])
                        exists_parent = db.query(models.Blacklist).filter(models.Blacklist.domain == parent).first()
                        if exists_parent:
                            return True
            except Exception as e:
                print(f"Error checking database blacklist: {e}")
                
        return False
        
    def check_openphish(self, url: str) -> bool:
        # Check direct match
        if url in self.openphish_urls:
            return True
        # Check domain match
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.split(":")[0].lower()
            for op_url in self.openphish_urls:
                if domain in op_url:
                    return True
        except Exception:
            pass
        return False

    def check_virustotal(self, url: str) -> Dict[str, Any]:
        """
        Check URL reputation using VirusTotal API.
        If no API key is set, returns a simulated result for testing.
        """
        if not self.vt_api_key:
            # Simulation for common test domains
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.split(":")[0].lower()
            
            # Check local blacklist
            if any(black_item in domain for black_item in LOCAL_BLACKLIST):
                return {
                    "is_flagged": True,
                    "malicious_count": 8,
                    "suspicious_count": 3,
                    "total_scanners": 92,
                    "source": "VirusTotal (Simulation)"
                }
            return {
                "is_flagged": False,
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_scanners": 92,
                "source": "VirusTotal (Simulation)"
            }

        # Actual VirusTotal API implementation
        import hashlib
        # VT URL ID is the SHA256 of the URL (without trailing slashes or normalized, but simple SHA256 is supported)
        url_id = hashlib.sha256(url.encode()).hexdigest()
        headers = {
            "accept": "application/json",
            "x-apikey": self.vt_api_key
        }
        
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                return {
                    "is_flagged": malicious > 0 or suspicious > 1,
                    "malicious_count": malicious,
                    "suspicious_count": suspicious,
                    "total_scanners": sum(stats.values()),
                    "source": "VirusTotal API"
                }
            elif response.status_code == 404:
                # If URL not scanned, submit it for scanning
                requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers, timeout=5)
                
            return {
                "is_flagged": False,
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_scanners": 0,
                "source": "VirusTotal API (Not Scanned Yet)"
            }
        except Exception as e:
            print(f"VirusTotal API error: {e}")
            return {
                "is_flagged": False,
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_scanners": 0,
                "source": f"VirusTotal Error: {str(e)}"
            }

    def check_safe_browsing(self, url: str) -> Dict[str, Any]:
        """
        Check URL reputation using Google Safe Browsing API.
        If no API key is set, returns a simulated result for testing.
        """
        if not self.gsb_api_key:
            # Check local blacklist
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.split(":")[0].lower()
            if any(black_item in domain for black_item in LOCAL_BLACKLIST):
                return {
                    "is_flagged": True,
                    "matches": ["SOCIAL_ENGINEERING"],
                    "source": "Google Safe Browsing (Simulation)"
                }
            return {
                "is_flagged": False,
                "matches": [],
                "source": "Google Safe Browsing (Simulation)"
            }

        # Actual Google Safe Browsing API call (Lookup API v4)
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.gsb_api_key}"
        payload = {
            "client": {
                "clientId": "phishguard-ai",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        try:
            response = requests.post(endpoint, json=payload, timeout=5)
            if response.status_code == 200:
                data = response.json()
                matches = data.get("matches", [])
                if matches:
                    threat_types = [m.get("threatType") for m in matches]
                    return {
                        "is_flagged": True,
                        "matches": threat_types,
                        "source": "Google Safe Browsing API"
                    }
            return {
                "is_flagged": False,
                "matches": [],
                "source": "Google Safe Browsing API"
            }
        except Exception as e:
            print(f"Google Safe Browsing API error: {e}")
            return {
                "is_flagged": False,
                "matches": [],
                "source": f"Google Safe Browsing Error: {str(e)}"
            }

    def scan_reputation(self, url: str, db=None) -> Dict[str, Any]:
        # Check cache first
        cached = self.get_cached_result(url)
        if cached:
            print(f"Reputation cache hit for: {url}")
            return cached

        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.split(":")[0].lower()
        
        # Check Whitelist first
        if self.check_whitelist(domain, db=db):
            result = {
                "is_whitelisted": True,
                "is_blacklisted": False,
                "is_flagged": False,
                "openphish_match": False,
                "virustotal": {"is_flagged": False, "malicious_count": 0, "suspicious_count": 0, "total_scanners": 0, "source": "Whitelist"},
                "safe_browsing": {"is_flagged": False, "matches": [], "source": "Whitelist"}
            }
            self.cache_result(url, result)
            return result
            
        # Check Blacklist second
        if self.check_blacklist(domain, db=db):
            result = {
                "is_whitelisted": False,
                "is_blacklisted": True,
                "is_flagged": True,
                "openphish_match": False,
                "virustotal": {"is_flagged": True, "malicious_count": 99, "suspicious_count": 0, "total_scanners": 99, "source": "Custom Blacklist Policy"},
                "safe_browsing": {"is_flagged": True, "matches": ["CUSTOM_BLACKLIST_POLICY"], "source": "Custom Blacklist Policy"}
            }
            self.cache_result(url, result)
            return result
            
        # Run other reputation scans
        openphish_match = self.check_openphish(url)
        vt_results = self.check_virustotal(url)
        gsb_results = self.check_safe_browsing(url)
        
        is_flagged = openphish_match or vt_results["is_flagged"] or gsb_results["is_flagged"]
        
        result = {
            "is_whitelisted": False,
            "is_blacklisted": False,
            "is_flagged": is_flagged,
            "openphish_match": openphish_match,
            "virustotal": vt_results,
            "safe_browsing": gsb_results
        }
        self.cache_result(url, result)
        return result
