import socket
import concurrent.futures
from typing import List, Dict, Any

HOMOGLYPHS = {
    'a': 'а',  # Cyrillic small letter a
    'c': 'с',  # Cyrillic small letter es
    'e': 'е',  # Cyrillic small letter ie
    'i': 'і',  # Cyrillic small letter byelorussian-ukrainian i
    'o': 'о',  # Cyrillic small letter o
    'p': 'р',  # Cyrillic small letter er
    's': 'ѕ',  # Cyrillic small letter dze
    'x': 'х',  # Cyrillic small letter ha
    'y': 'у',  # Cyrillic small letter u
}

def generate_homoglyph(domain: str) -> str:
    # Replace the first replaceable character found
    for char, replacement in HOMOGLYPHS.items():
        if char in domain:
            return domain.replace(char, replacement, 1)
    return domain

def generate_typosquats(domain: str) -> List[Dict[str, Any]]:
    # Split domain and TLD
    parts = domain.split(".")
    if len(parts) < 2:
        return []
    
    name = parts[0]
    tld = ".".join(parts[1:])
    
    variants = []
    
    # 1. Homoglyph substitution
    homo_name = generate_homoglyph(name)
    if homo_name != name:
        variants.append({
            "variant": f"{homo_name}.{tld}",
            "type": "Homoglyph Attack"
        })
        
    # 2. Omission typo
    if len(name) > 3:
        variants.append({
            "variant": f"{name[:-1]}.{tld}",
            "type": "Character Omission"
        })
        
    # 3. Transposition typo
    if len(name) > 2:
        transposed = name[:-2] + name[-1] + name[-2]
        variants.append({
            "variant": f"{transposed}.{tld}",
            "type": "Character Transposition"
        })
        
    # 4. Insertion/Doubling typo
    if len(name) > 1:
        doubled = name + name[-1]
        variants.append({
            "variant": f"{doubled}.{tld}",
            "type": "Character Doubling"
        })
        
    # 5. Common subdomains/Prepend
    variants.append({
        "variant": f"login-{name}.{tld}",
        "type": "Deceptive Prefix"
    })
    variants.append({
        "variant": f"secure-{name}.{tld}",
        "type": "Deceptive Prefix"
    })
    
    # Resolve online status concurrently to keep response times fast
    results = []
    
    def check_status(item):
        variant = item["variant"]
        try:
            # Simple DNS resolution
            ip = socket.gethostbyname(variant)
            return {
                "variant": variant,
                "type": item["type"],
                "is_online": True,
                "ip": ip
            }
        except Exception:
            return {
                "variant": variant,
                "type": item["type"],
                "is_online": False,
                "ip": "N/A"
            }
            
    # Execute checks in a thread pool (max 1.5s timeout)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(check_status, item): item for item in variants}
        concurrent.futures.wait(futures, timeout=1.5)
        
        for future in futures:
            try:
                results.append(future.result())
            except Exception:
                # Fallback to offline
                item = futures[future]
                results.append({
                    "variant": item["variant"],
                    "type": item["type"],
                    "is_online": False,
                    "ip": "N/A"
                })
                
    return results
