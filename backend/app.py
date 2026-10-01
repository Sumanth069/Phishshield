"""
PhishShield AI - FastAPI Backend Microservice (v1.4 with Quishing & NLP Urgency)
Endpoints:
- POST /api/v1/analyze : Full forensic inspection of headers, domains, links, attachments, QR images, and body text
- POST /api/v1/scan-qr : Dedicated standalone Quishing image scanner endpoint
- GET  /api/v1/health  : Microservice health check
- GET  /api/v1/allowlist : Retrieve user allowlist
- POST /api/v1/allowlist : Add trusted domain to allowlist
"""

import time
import asyncio
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from domain_forensics import analyze_domain
from header_analyzer import analyze_headers
from url_unshortener import unshorten_url
from reputation import check_domain_reputation
from qr_scanner import decode_qr_from_base64
from nlp_urgency import analyze_psychological_intent
from scoring import calculate_composite_score

app = FastAPI(
    title="PhishShield AI - Forensic Defense Engine",
    description="High-concurrency microservice for email header analysis, lookalike domain detection, Quishing QR extraction, and SSRF-hardened link inspection.",
    version="1.4.0"
)

# Enable CORS for browser extensions and localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

USER_ALLOWLIST = {"github.com", "google.com", "microsoft.com"}

# ----------------- Request / Response Models -----------------

class LinkItem(BaseModel):
    text: str = ""
    href: str = ""

class AttachmentItem(BaseModel):
    name: str = ""
    size_str: Optional[str] = None
    type: Optional[str] = None

class AnalyzeEmailRequest(BaseModel):
    message_id: str = "msg_unknown"
    subject: str = ""
    body_text: Optional[str] = ""
    from_name: str = ""
    from_address: str = ""
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    auth_results: Optional[str] = None
    mailed_by: Optional[str] = None
    signed_by: Optional[str] = None
    links: List[LinkItem] = []
    attachments: List[AttachmentItem] = []
    images: List[str] = [] # Base64 encoded images or data URIs for QR Quishing scan

class ScoreItem(BaseModel):
    reason: str
    points: int
    mitre: Optional[str] = None

class MitreItem(BaseModel):
    id: str
    name: str

class AnalyzeEmailResponse(BaseModel):
    message_id: str
    total_score: int
    verdict: str  # SAFE | SUSPICIOUS | CRITICAL_PHISHING
    risk_tier: str  # safe | warning | danger
    is_allowlisted: bool
    score_breakdown: List[ScoreItem]
    mitre_attack_techniques: List[MitreItem]
    teachable_moment: str
    inspected_links: List[Dict[str, Any]]
    qr_findings: List[Dict[str, Any]]
    execution_time_ms: float

class QrScanRequest(BaseModel):
    image_base64: str

# ----------------- API Endpoints -----------------

@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "online",
        "service": "PhishShield AI Forensic Defense Engine",
        "version": "1.4.0",
        "features": ["Quishing QR Scanner (OpenCV)", "NLP Urgency Coercion", "SSRF Unshortener", "Header Forensics"],
        "allowlist_count": len(USER_ALLOWLIST)
    }

@app.post("/api/v1/scan-qr")
async def scan_qr_endpoint(payload: QrScanRequest):
    """Standalone endpoint to scan a single image for Quishing QR codes."""
    res = decode_qr_from_base64(payload.image_base64)
    if res.get("found"):
        url = res.get("url")
        unshortened = await unshorten_url(url)
        dest_domain = unshortened.get("final_url", "").split("://")[-1].split("/")[0].split(":")[0]
        domain_info = analyze_domain(dest_domain)
        rep = await check_domain_reputation(dest_domain)
        return {
            "found": True,
            "url": url,
            "unshortened": unshortened,
            "domain_info": domain_info,
            "reputation": rep
        }
    return {"found": False, "url": None, "error": res.get("error")}

@app.get("/api/v1/allowlist")
async def get_allowlist():
    return {"allowlist": sorted(list(USER_ALLOWLIST))}

@app.post("/api/v1/allowlist")
async def add_to_allowlist(payload: Dict[str, str]):
    domain = payload.get("domain", "").strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")
    USER_ALLOWLIST.add(domain)
    return {"status": "success", "added": domain, "allowlist": sorted(list(USER_ALLOWLIST))}

@app.post("/api/v1/analyze", response_model=AnalyzeEmailResponse)
async def analyze_email(req: AnalyzeEmailRequest):
    start_time = time.perf_counter()

    from_domain = req.from_address.split("@")[-1].lower() if "@" in req.from_address else ""
    is_allowlisted = from_domain in USER_ALLOWLIST

    # 1. Header & Display Name Forensics
    header_res = analyze_headers(
        from_name=req.from_name,
        from_address=req.from_address,
        reply_to=req.reply_to,
        return_path=req.return_path,
        auth_results_str=req.auth_results,
        mailed_by=req.mailed_by,
        signed_by=req.signed_by
    )

    # 2. Sender Domain Forensics
    domain_res = analyze_domain(from_domain)

    # 3. Quishing Computer Vision Scanner on Embedded Images
    qr_res_list = []
    qr_links_to_inspect = []
    for img_b64 in req.images[:5]: # Max 5 images per email
        qr_decode = decode_qr_from_base64(img_b64)
        if qr_decode.get("found"):
            qr_res_list.append(qr_decode)
            qr_links_to_inspect.append(qr_decode["url"])

    # 4. Psychological Coercion & Urgency NLP Scanner
    full_text_to_scan = f"{req.subject}\n{req.body_text or ''}"
    urgency_res = analyze_psychological_intent(full_text_to_scan)

    # 5. Anchor Text Discrepancies & Link Inspection
    anchor_discrepancies = []
    links_to_inspect = list(qr_links_to_inspect) # Include decoded QR links

    for l in req.links[:8]:
        text = l.text.strip()
        href = l.href.strip()
        if not href or href.startswith("mailto:") or href.startswith("#"):
            continue

        if ("." in text and ("http" in text or "www" in text or ".com" in text or ".org" in text)):
            clean_text = text.replace("http://", "").replace("https://", "").replace("www.", "").split("/")[0].lower()
            clean_href = href.replace("http://", "").replace("https://", "").replace("www.", "").split("/")[0].lower()
            if clean_text != clean_href:
                anchor_discrepancies.append({"text": text, "href": href})

        links_to_inspect.append(href)

    async def inspect_single_link(link_url: str):
        unshortened = await unshorten_url(link_url)
        dest_domain = unshortened.get("final_url", "").split("://")[-1].split("/")[0].split(":")[0]
        rep = await check_domain_reputation(dest_domain)
        return {**unshortened, **rep}

    url_res_list = await asyncio.gather(*[inspect_single_link(u) for u in links_to_inspect])

    # 6. Attachment Risk Scan
    attachment_flags = []
    for att in req.attachments:
        name = att.name.lower()
        if name.endswith(".html") or name.endswith(".htm"):
            attachment_flags.append(f"HTML attachment '{att.name}' (credential harvester risk)")
        elif name.endswith(".exe") or ".pdf.exe" in name or ".doc.exe" in name:
            attachment_flags.append(f"Executable/Double extension file '{att.name}'")
        elif name.endswith(".zip") or name.endswith(".iso") or name.endswith(".rar"):
            attachment_flags.append(f"Archive file '{att.name}'")

    # 7. Composite Additive Scoring with Quishing & Urgency
    final_verdict = calculate_composite_score(
        header_res=header_res,
        domain_res=domain_res,
        url_res_list=url_res_list,
        attachment_flags=attachment_flags,
        anchor_discrepancies=anchor_discrepancies,
        qr_res_list=qr_res_list,
        urgency_res=urgency_res,
        is_allowlisted=is_allowlisted
    )

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    return AnalyzeEmailResponse(
        message_id=req.message_id,
        total_score=final_verdict["total_score"],
        verdict=final_verdict["verdict"],
        risk_tier=final_verdict["risk_tier"],
        is_allowlisted=final_verdict["is_allowlisted"],
        score_breakdown=[ScoreItem(**b) for b in final_verdict["score_breakdown"]],
        mitre_attack_techniques=[MitreItem(**m) for m in final_verdict["mitre_attack_techniques"]],
        teachable_moment=final_verdict["teachable_moment"],
        inspected_links=url_res_list,
        qr_findings=qr_res_list,
        execution_time_ms=round(elapsed_ms, 2)
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
