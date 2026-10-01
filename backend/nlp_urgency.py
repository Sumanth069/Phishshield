"""
Psychological Coercion & Urgency NLP Scanner
- Identifies artificial urgency vectors designed to rush human decision-making
- Detects executive authority manipulation (BEC wire/gift card pretexts)
- Detects credential access pretexting ("password expired", "session terminated")
"""

import re
from typing import Dict, Any, List

URGENCY_PATTERNS = [
    (r"\b(?:within|in)\s+(?:2|12|24|48)\s+hours?\b", "Strict deadline constraint (<48h)"),
    (r"\b(?:immediate|immediately|urgent|urgently|right away|asap)\b", "Artificial urgency trigger"),
    (r"\b(?:final\s+notice|last\s+warning|termination\s+notice)\b", "Severe consequence threat"),
    (r"\b(?:suspended|locked|deactivated|disabled|restricted)\b", "Account suspension threat"),
    (r"\b(?:expire(?:s|d)?\s+today|expiring\s+soon)\b", "Imminent expiration claim")
]

BEC_AUTHORITY_PATTERNS = [
    (r"\b(?:confidential\s+(?:task|request|call)|keep\s+this\s+quiet)\b", "Confidentiality pressure / channel isolation"),
    (r"\b(?:wire\s+transfer|gift\s+cards?|direct\s+deposit|payroll\s+update)\b", "Financial transaction request (BEC vector)"),
    (r"\b(?:tied\s+up\s+in|off-site|conference\s+call|do\s+not\s+call\s+me)\b", "Out-of-band communication block")
]

CREDENTIAL_PRETEXT_PATTERNS = [
    (r"\b(?:retain\s+your\s+password|update\s+your\s+password|password\s+expir(?:ed|ation))\b", "Password renewal pretext"),
    (r"\b(?:verify\s+your\s+(?:account|identity|session|credentials))\b", "Identity verification pretext"),
    (r"\b(?:re-enroll|re-authenticate|mfa\s+(?:app|verification))\b", "MFA/2FA re-enrollment lure")
]

def analyze_psychological_intent(text: str) -> Dict[str, Any]:
    """
    Scans plain text body for psychological manipulation triggers.
    """
    if not text:
        return {"points": 0, "triggers": [], "indicators": []}

    text_lower = text.lower()
    triggers = []
    points = 0

    # 1. Urgency Triggers
    found_urgency = []
    for pattern, desc in URGENCY_PATTERNS:
        match = re.search(pattern, text_lower)
        if match:
            found_urgency.append(f"Urgency cue: '{match.group(0)}' ({desc})")
    
    if found_urgency:
        points += 15
        triggers.extend(found_urgency)

    # 2. BEC Authority Triggers
    found_bec = []
    for pattern, desc in BEC_AUTHORITY_PATTERNS:
        match = re.search(pattern, text_lower)
        if match:
            found_bec.append(f"Coercion cue: '{match.group(0)}' ({desc})")
    
    if found_bec:
        points += 20
        triggers.extend(found_bec)

    # 3. Credential Pretext Triggers
    found_cred = []
    for pattern, desc in CREDENTIAL_PRETEXT_PATTERNS:
        match = re.search(pattern, text_lower)
        if match:
            found_cred.append(f"Pretext cue: '{match.group(0)}' ({desc})")
    
    if found_cred:
        points += 15
        triggers.extend(found_cred)

    indicators = []
    if points > 0:
        indicators.append(f"Psychological Manipulation: {len(triggers)} urgency/coercion cue(s) detected in text")

    return {
        "points": points,
        "triggers": triggers,
        "indicators": indicators
    }
