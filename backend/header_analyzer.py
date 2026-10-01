"""
Header Forensics Module
- Ingests headers from HeaderProvider (view=om or DOM details)
- Evaluates SPF, DKIM, and DMARC authentication alignment
- Detects Display-Name Spoofing (e.g. "PayPal Support" <random@gmail.com>)
- Detects envelope address spoofing (From vs Return-Path vs Reply-To)
"""

import re
from typing import Dict, Any, List, Optional
import tldextract

FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "ymail.com",
    "hotmail.com", "outlook.com", "live.com", "msn.com",
    "proton.me", "protonmail.com", "icloud.com", "me.com",
    "aol.com", "zoho.com", "mail.com", "gmx.com"
}

BRAND_KEYWORDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "chase", "wells fargo", "bank of america", "docusign", "dropbox",
    "support", "security", "helpdesk", "account team", "billing",
    "administrator", "it department", "hr department", "payroll"
]

def parse_authentication_results(auth_header: str) -> Dict[str, str]:
    """
    Parses SPF, DKIM, DMARC statuses from Authentication-Results string.
    e.g. "spf=pass ... dkim=pass ... dmarc=pass"
    """
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    if not auth_header:
        return results

    auth_lower = auth_header.lower()

    # Match dkim
    dkim_match = re.search(r'\bdkim=(pass|fail|softfail|neutral|none)\b', auth_lower)
    if dkim_match:
        results["dkim"] = dkim_match.group(1)

    # Match spf
    spf_match = re.search(r'\bspf=(pass|fail|softfail|neutral|none)\b', auth_lower)
    if spf_match:
        results["spf"] = spf_match.group(1)

    # Match dmarc
    dmarc_match = re.search(r'\bdmarc=(pass|fail|none)\b', auth_lower)
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1)

    return results

def analyze_headers(
    from_name: str,
    from_address: str,
    reply_to: Optional[str] = None,
    return_path: Optional[str] = None,
    auth_results_str: Optional[str] = None,
    mailed_by: Optional[str] = None,
    signed_by: Optional[str] = None
) -> Dict[str, Any]:
    """
    Performs forensic analysis of email headers and sender metadata.
    """
    indicators: List[str] = []
    points = 0

    from_address = (from_address or "").strip().lower()
    from_name = (from_name or "").strip()
    from_domain = from_address.split("@")[-1] if "@" in from_address else ""

    reply_to = (reply_to or "").strip().lower()
    reply_to_domain = reply_to.split("@")[-1] if "@" in reply_to else ""

    return_path = (return_path or "").strip().lower()
    return_path_domain = return_path.split("@")[-1] if "@" in return_path else ""

    # 1. Check Display-Name Impersonation
    # If the display name contains a sensitive brand/entity, but is sent from a free email provider
    from_name_lower = from_name.lower()
    detected_spoofed_brand = None
    for brand in BRAND_KEYWORDS:
        if brand in from_name_lower:
            detected_spoofed_brand = brand
            break

    is_free_webmail = from_domain in FREE_WEBMAIL_DOMAINS
    if detected_spoofed_brand and is_free_webmail:
        points += 30
        indicators.append(
            f"Display-Name Spoofing: Display name contains '{detected_spoofed_brand}', but sending address is a personal free account (@{from_domain})"
        )

    # 2. Check Reply-To vs From discrepancy
    if reply_to and reply_to_domain and from_domain:
        from_reg = tldextract.extract(from_domain).registered_domain
        reply_reg = tldextract.extract(reply_to_domain).registered_domain
        if from_reg != reply_reg:
            points += 20
            indicators.append(
                f"Reply-To Mismatch: Replies directed to '{reply_to}' instead of sender '{from_address}'"
            )

    # 3. Check Return-Path vs From (Envelope Spoofing)
    if return_path and return_path_domain and from_domain:
        from_reg = tldextract.extract(from_domain).registered_domain
        return_reg = tldextract.extract(return_path_domain).registered_domain
        if from_reg != return_reg and return_reg not in ["google.com", "amazonses.com", "sendgrid.net", "mailgun.org"]:
            points += 15
            indicators.append(
                f"Envelope Sender Discrepancy: Return-Path domain '{return_path_domain}' does not align with From domain '{from_domain}'"
            )

    # 4. Check Authentication-Results (SPF, DKIM, DMARC)
    auth_data = parse_authentication_results(auth_results_str or "")
    
    # If signed_by is provided from DOM Details (Fallback provider)
    if signed_by and from_domain:
        from_reg = tldextract.extract(from_domain).registered_domain
        signed_reg = tldextract.extract(signed_by).registered_domain
        if signed_reg and from_reg != signed_reg and signed_reg not in ["google.com", "sendgrid.net", "mailgun.org"]:
            points += 20
            indicators.append(f"DKIM Signature Mismatch: Email signed by '{signed_by}', not '{from_domain}'")

    if auth_data.get("dkim") == "fail":
        points += 20
        indicators.append("DKIM cryptographic signature verification FAILED")
    
    if auth_data.get("spf") == "fail":
        points += 20
        indicators.append(f"SPF alignment check FAILED for sending server and domain '{from_domain}'")

    if auth_data.get("dmarc") == "fail":
        points += 25
        indicators.append("DMARC domain policy validation FAILED")

    return {
        "from_address": from_address,
        "from_name": from_name,
        "from_domain": from_domain,
        "is_free_webmail": is_free_webmail,
        "auth_results": auth_data,
        "points": points,
        "indicators": indicators,
        "display_name_spoof": detected_spoofed_brand if is_free_webmail else None
    }
