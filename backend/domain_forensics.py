"""
Domain Forensics Module
- RapidFuzz C++ Levenshtein distance against top targeted enterprise brands (< 2ms)
- IDN Punycode homoglyph detection (xn--)
- Subdomain stacking and brand keyword hijacking checks
"""

import math
from typing import Dict, Any, List, Optional
import tldextract
from rapidfuzz.distance import Levenshtein

# Top targeted corporate and consumer brands commonly spoofed
TARGETED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "citibank", "docusign",
    "dropbox", "adobe", "facebook", "instagram", "linkedin", "twitter",
    "coinbase", "binance", "stripe", "github", "zoom", "fedex", "dhl",
    "usps", "walmart", "irs", "att", "verizon"
]

# Legitimate domains for these brands
LEGITIMATE_DOMAINS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "azure.com"],
    "google": ["google.com", "gmail.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "bankofamerica": ["bankofamerica.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "adobe": ["adobe.com"],
    "facebook": ["facebook.com", "meta.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com"],
    "coinbase": ["coinbase.com"],
    "stripe": ["stripe.com"],
    "github": ["github.com"],
    "zoom": ["zoom.us"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com"],
    "usps": ["usps.com"]
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "buzz", "rest", "surf", "fit", "work",
    "gq", "cf", "tk", "ml", "ga", "country", "stream", "live", "link"
}

def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect algorithmic random domain generation (DGA)."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def analyze_domain(domain_str: str) -> Dict[str, Any]:
    """
    Performs forensic analysis on a domain string:
    - Registered domain & TLD extraction
    - Lookalike typosquatting vs known brands
    - IDN Punycode homoglyphs (xn--)
    - Subdomain brand hijacking
    """
    if not domain_str:
        return {"domain": "", "is_suspicious": False, "score": 0, "indicators": []}

    domain_str = domain_str.strip().lower()
    # Strip any protocol or paths if passed
    if "://" in domain_str:
        domain_str = domain_str.split("://")[1].split("/")[0].split(":")[0]
    else:
        domain_str = domain_str.split("/")[0].split(":")[0]

    extracted = tldextract.extract(domain_str)
    domain_name = extracted.domain # e.g. 'paypaI' or 'microsoft'
    tld = extracted.suffix # e.g. 'com' or 'top'
    subdomain = extracted.subdomain # e.g. 'login.verify'
    registered_domain = f"{domain_name}.{tld}" if tld else domain_name

    indicators: List[str] = []
    points = 0

    # 1. Check IDN Punycode Homoglyph attack
    is_punycode = domain_str.startswith("xn--") or ".xn--" in domain_str
    if is_punycode:
        points += 35
        indicators.append("Punycode / IDN Homoglyph domain detected (xn--)")

    # 2. Check Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        points += 15
        indicators.append(f"Suspicious high-risk TLD detected (.{tld})")

    # 3. Check Typosquatting / Lookalike against top brands
    detected_lookalike = None
    target_brand_found = None

    for brand in TARGETED_BRANDS:
        legit_domains = LEGITIMATE_DOMAINS.get(brand, [f"{brand}.com"])
        
        # If this is literally the official domain, it's legitimate
        if registered_domain in legit_domains:
            return {
                "domain": domain_str,
                "registered_domain": registered_domain,
                "is_legitimate_brand": True,
                "brand": brand,
                "is_suspicious": False,
                "score": 0,
                "indicators": []
            }

        # Calculate Levenshtein distance
        dist = Levenshtein.distance(domain_name, brand)
        ratio = Levenshtein.normalized_similarity(domain_name, brand)

        # Catch 1 or 2 character edit distance (e.g. paypaI, micros0ft)
        if 0 < dist <= 2 and ratio >= 0.75:
            points += 35
            detected_lookalike = brand
            indicators.append(
                f"Lookalike typosquatting domain: '{domain_name}' mimics trusted brand '{brand}' (Distance: {dist})"
            )
            break

        # Check if brand keyword is embedded in subdomain or hyphenated domain
        # e.g. paypal-security-update.com or paypal.verify-login.com
        if brand in domain_name and domain_name != brand:
            points += 30
            indicators.append(f"Brand keyword '{brand}' hijacked in hyphenated domain '{domain_name}'")
            break
        elif brand in subdomain:
            points += 25
            indicators.append(f"Brand keyword '{brand}' spoofed inside subdomain '{subdomain}'")
            break

    # 4. Check Subdomain Stacking / Entropy
    if subdomain.count(".") >= 2:
        points += 15
        indicators.append(f"Excessive subdomain nesting detected ({subdomain})")

    entropy = calculate_shannon_entropy(domain_name)
    if entropy > 3.8 and len(domain_name) > 12:
        points += 15
        indicators.append(f"High domain entropy ({entropy:.2f}), possible algorithmically generated domain")

    return {
        "domain": domain_str,
        "registered_domain": registered_domain,
        "is_legitimate_brand": False,
        "is_suspicious": points > 0,
        "score": points,
        "indicators": indicators,
        "lookalike_brand": detected_lookalike
    }
