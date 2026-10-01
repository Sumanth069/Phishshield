"""
Additive Risk Scoring Engine (Hardened v1.4 with Quishing & NLP Urgency)
- Transparent, auditable point accumulation
- Integrated Quishing (QR code) detection (+40 pts)
- Integrated Psychological Urgency & Coercion scoring (+15 to +35 pts)
- Generates MITRE ATT&CK framework mapping for SOC triage
"""

from typing import Dict, Any, List

def calculate_composite_score(
    header_res: Dict[str, Any],
    domain_res: Dict[str, Any],
    url_res_list: List[Dict[str, Any]],
    attachment_flags: List[str],
    anchor_discrepancies: List[Dict[str, Any]],
    qr_res_list: List[Dict[str, Any]] = None,
    urgency_res: Dict[str, Any] = None,
    is_allowlisted: bool = False
) -> Dict[str, Any]:
    """
    Computes transparent additive score across all inspection modules.
    """
    if is_allowlisted:
        return {
            "total_score": 0,
            "verdict": "SAFE",
            "risk_tier": "allowlisted",
            "is_allowlisted": True,
            "score_breakdown": [{"reason": "Sender domain is on your trusted allowlist", "points": 0, "mitre": "None"}],
            "mitre_attack_techniques": [],
            "teachable_moment": "This email is from a sender domain you previously marked as safe."
        }

    total_score = 0
    breakdown: List[Dict[str, Any]] = []
    mitre_tags: List[Dict[str, str]] = []

    # 1. Header & Display-Name Spoofing (MITRE T1534 / T1566)
    if header_res.get("points", 0) > 0:
        for ind in header_res.get("indicators", []):
            pts = 30 if "Display-Name" in ind else 20
            total_score += pts
            breakdown.append({
                "reason": ind,
                "points": pts,
                "mitre": "T1534: Internal Spearphishing / Impersonation"
            })
            mitre_tags.append({"id": "T1534", "name": "Display-Name Spoofing"})

    # 2. Sender Domain Forensics (MITRE T1071.001)
    if domain_res.get("points", 0) > 0:
        for ind in domain_res.get("indicators", []):
            pts = 35 if "Lookalike" in ind or "Punycode" in ind else 15
            total_score += pts
            breakdown.append({
                "reason": ind,
                "points": pts,
                "mitre": "T1071.001: Web Protocols (Lookalike Domain / Homoglyph)"
            })
            mitre_tags.append({"id": "T1071.001", "name": "Typosquatting & Homoglyphs"})

    # 3. Quishing (QR Code Phishing) (MITRE T1566.002)
    for qr in (qr_res_list or []):
        if qr.get("found"):
            pts = 40
            total_score += pts
            decoded = qr.get("url", "")
            breakdown.append({
                "reason": f"🚨 Quishing Attack: Embedded QR Code contains external destination link '{decoded}'",
                "points": pts,
                "mitre": "T1566.002: Spearphishing Attachment / Image (Quishing)"
            })
            mitre_tags.append({"id": "T1566.002", "name": "Quishing (QR Code Phishing)"})

    # 4. Psychological Coercion & Urgency NLP
    if urgency_res and urgency_res.get("points", 0) > 0:
        pts = urgency_res.get("points", 15)
        total_score += pts
        for trig in urgency_res.get("triggers", []):
            breakdown.append({
                "reason": f"Psychological Pressure: {trig}",
                "points": 5,
                "mitre": "T1566: Social Engineering Coercion"
            })
        mitre_tags.append({"id": "T1566", "name": "Urgency & Emotional Coercion"})

    # 5. URL & Landing Page Findings (MITRE T1566.001)
    for u in url_res_list:
        if u.get("is_blacklisted"):
            pts = 50
            total_score += pts
            breakdown.append({
                "reason": f"Destination URL '{u.get('final_url')}' is on threat feeds",
                "points": pts,
                "mitre": "T1566.001: Spearphishing Link"
            })
        if u.get("is_newly_registered"):
            pts = 25
            total_score += pts
            breakdown.append({
                "reason": f"Destination domain registered &lt; 30 days ago",
                "points": pts,
                "mitre": "T1583.001: Domains (Newly Registered)"
            })
        if u.get("ssrf_blocked"):
            pts = 40
            total_score += pts
            breakdown.append({
                "reason": "URL redirects to private/restricted internal IP (SSRF probe)",
                "points": pts,
                "mitre": "T1595: Active Scanning (SSRF)"
            })

    # 6. Anchor Text Discrepancies
    for ad in anchor_discrepancies:
        pts = 20
        total_score += pts
        breakdown.append({
            "reason": f"Anchor text deceptive: Visible text '{ad.get('text')}' points to '{ad.get('href')}'",
            "points": pts,
            "mitre": "T1566.001: Deceptive Hyperlink"
        })
        mitre_tags.append({"id": "T1566.001", "name": "Spearphishing Link"})

    # 7. Attachment Risks
    for att in attachment_flags:
        pts = 20
        total_score += pts
        breakdown.append({
            "reason": f"High-risk attachment: {att}",
            "points": pts,
            "mitre": "T1566.002: Spearphishing Attachment"
        })
        mitre_tags.append({"id": "T1566.002", "name": "Weaponized Attachment"})

    # Determine Verdict Tier
    if total_score >= 50:
        verdict = "CRITICAL_PHISHING"
        risk_tier = "danger"
    elif total_score >= 25:
        verdict = "SUSPICIOUS"
        risk_tier = "warning"
    else:
        verdict = "SAFE"
        risk_tier = "safe"

    # Deduplicate MITRE tags
    unique_mitre = list({m["id"]: m for m in mitre_tags}.values())

    # Generate Teachable Moment
    teachable_moment = generate_teachable_moment(breakdown)

    return {
        "total_score": min(total_score, 100),
        "verdict": verdict,
        "risk_tier": risk_tier,
        "is_allowlisted": False,
        "score_breakdown": breakdown,
        "mitre_attack_techniques": unique_mitre,
        "teachable_moment": teachable_moment
    }

def generate_teachable_moment(breakdown: List[Dict[str, Any]]) -> str:
    """Creates a concise, human-friendly explanation of the avoided threats for user awareness."""
    if not breakdown:
        return "Always verify link destinations before entering credentials or sensitive passwords."

    reasons = [b["reason"].lower() for b in breakdown]

    if any("quishing" in r for r in reasons):
        return (
            "Security Tip: Quishing (QR Phishing) tricks you into using your personal phone camera to open malicious links, bypassing company computer firewalls. Never scan unexpected QR codes in emails!"
        )
    if any("display-name" in r for r in reasons):
        return (
            "Security Tip: Attackers often change their Display Name to 'Support' or 'Security', but their real email address reveals a free personal account (@gmail.com). Always check the actual address inside the angle brackets!"
        )
    if any("lookalike" in r for r in reasons):
        return (
            "Security Tip: Lookalike domains swap similar-looking characters (like a capital 'I' for lowercase 'l' or '0' for 'o') to trick you into visiting fake login portals."
        )
    if any("anchor text" in r for r in reasons):
        return (
            "Security Tip: The blue link text in an email can say whatever the sender wants. Hover over links or check the actual destination URL before clicking."
        )
    if any("psychological" in r for r in reasons or "urgency" in r for r in reasons):
        return (
            "Security Tip: Attackers use artificial urgency ('within 2 hours') or claim to be executives in confidential meetings to panic you into taking immediate action without thinking."
        )
    
    return "Security Tip: Attackers rely on urgent language and unauthenticated domains to rush you into making mistakes. Take 10 seconds to verify before taking action."
