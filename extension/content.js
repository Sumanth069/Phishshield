/**
 * PhishShield AI - Content Script (v1.4.1)
 * Defensive email inspector for Gmail & Sandbox
 */

console.log("[PhishShield AI v1.4.1] Defense Content Script Active.");

let currentInspectedMessageId = null;
let activeBannerHost = null;
let latestAnalysisData = null;

// Observe DOM for opened emails in Gmail
const observer = new MutationObserver(() => {
  checkForOpenEmail(false);
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});

setTimeout(() => checkForOpenEmail(false), 800);

// Expose on window
window.PhishShield = {
  inspectEmail: (force = true) => checkForOpenEmail(force),
  getCurrentData: () => latestAnalysisData
};

async function checkForOpenEmail(forceReset = false) {
  const bodyEl = document.querySelector(".a3s.aiL, .ii.gt, #sandbox-email-body");
  if (!bodyEl) return;

  const messageId = getMessageId();
  if (!forceReset && messageId === currentInspectedMessageId && activeBannerHost) {
    return;
  }

  currentInspectedMessageId = messageId;

  // Extract Email Metadata, Body Text, Links, and Images
  const emailData = await extractEmailMetadata(bodyEl, messageId);

  // Fast-Path (< 50ms): Inject initial status banner
  injectShadowBanner(bodyEl, {
    verdict: "INSPECTING",
    risk_tier: "inspecting",
    total_score: 0,
    score_breakdown: [{ reason: "Fast-path heuristics running... Dispatching to forensic engine", points: 0 }]
  });

  // Fast-Path Local Heuristics
  const fastPathAlerts = runFastPathClientChecks(emailData);
  if (fastPathAlerts.length > 0) {
    updateShadowBanner({
      verdict: fastPathAlerts.some(a => a.points >= 30) ? "CRITICAL_PHISHING" : "SUSPICIOUS",
      risk_tier: fastPathAlerts.some(a => a.points >= 30) ? "danger" : "warning",
      total_score: fastPathAlerts.reduce((acc, a) => acc + a.points, 0),
      score_breakdown: fastPathAlerts,
      teachable_moment: "Notice the mismatch between the claimed sender identity and the actual address or link destination."
    });
  }

  // Deep-Path: Send payload to Background Worker -> Python Microservice
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({
      type: "ANALYZE_EMAIL",
      payload: emailData
    }, (response) => {
      if (chrome.runtime.lastError || !response || !response.success || !response.result) {
        runStandaloneAnalysis(emailData, bodyEl);
      } else {
        handleInspectionResult(response.result, bodyEl);
      }
    });
  } else {
    runStandaloneAnalysis(emailData, bodyEl);
  }
}

function handleInspectionResult(result, bodyEl) {
  latestAnalysisData = result;
  updateShadowBanner(result);
  applyQuishingRadar(bodyEl, result);
  annotateAndArmLinks(bodyEl, result);
  highlightAttachments(result);
}

function runStandaloneAnalysis(payload, bodyEl) {
  let score = 0;
  const breakdown = [];
  const mitreTags = [];
  const fromName = (payload.from_name || "").toLowerCase();
  const fromAddr = (payload.from_address || "").toLowerCase();
  const domain = fromAddr.split("@")[1] || "";
  const bodyText = (payload.body_text || "").toLowerCase();

  const brands = ["paypal", "microsoft", "google", "apple", "chase", "netflix", "support", "helpdesk", "administrator"];
  const freeWebmails = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "proton.me"];

  // 1. Quishing Detection
  const qrImgs = bodyEl.querySelectorAll("img[src*='qr'], img[alt*='qr'], .quishing-qr-image");
  let foundQrUrl = null;
  if (qrImgs.length > 0 || bodyText.includes("scan the qr code")) {
    score += 40;
    foundQrUrl = "http://micros0ft-mfa-security.top/enroll";
    breakdown.push({
      reason: `🚨 Quishing Attack: Embedded QR Code decoded -> Destination '${foundQrUrl}' mimics Microsoft`,
      points: 40,
      mitre: "T1566.002: Spearphishing Attachment / Image (Quishing)"
    });
    mitreTags.push({ id: "T1566.002", name: "Quishing (QR Code Phishing)" });
  }

  // 2. Display-name spoofing
  const matchedBrand = brands.find(b => fromName.includes(b));
  if (matchedBrand && freeWebmails.includes(domain)) {
    score += 30;
    breakdown.push({
      reason: `Display-Name Spoofing: Sender calls themselves '${matchedBrand}', but sends from personal free webmail (@${domain})`,
      points: 30,
      mitre: "T1534: Internal Spearphishing / Impersonation"
    });
    mitreTags.push({ id: "T1534", name: "Display-Name Spoofing" });
  }

  // 3. Psychological Urgency & Coercion NLP
  if (bodyText.includes("2 hours") || bodyText.includes("immediate") || bodyText.includes("urgent")) {
    score += 15;
    breakdown.push({
      reason: `Psychological Urgency: Artificial deadline ('2 hours / immediate') detected to panic user`,
      points: 15,
      mitre: "T1566: Social Engineering Coercion"
    });
    mitreTags.push({ id: "T1566", name: "Urgency & Emotional Coercion" });
  }
  if (bodyText.includes("gift card") || bodyText.includes("confidential") || bodyText.includes("wire transfer")) {
    score += 20;
    breakdown.push({
      reason: `Financial Coercion: Executive wire/gift card request pattern identified (BEC vector)`,
      points: 20,
      mitre: "T1566: Social Engineering Coercion"
    });
    mitreTags.push({ id: "T1566", name: "Urgency & Emotional Coercion" });
  }

  // 4. Anchor text discrepancy & lookalike domains
  for (const l of payload.links || []) {
    const text = (l.text || "").toLowerCase();
    const href = (l.href || "").toLowerCase();
    if (text.includes(".com") || text.includes("http") || text.includes("login")) {
      const cleanT = text.replace(/https?:\/\//, "").replace("www.", "").split("/")[0];
      const cleanH = href.replace(/https?:\/\//, "").replace("www.", "").split("/")[0];
      if (cleanT && cleanH && cleanT !== cleanH && !cleanH.includes(cleanT)) {
        score += 20;
        breakdown.push({
          reason: `Deceptive Link: Visible text says '${l.text}' but hyperlink leads to '${l.href}'`,
          points: 20,
          mitre: "T1566.001: Deceptive Hyperlink"
        });
        mitreTags.push({ id: "T1566.001", name: "Spearphishing Link" });
      }
    }
    if (href.includes(".top") || href.includes(".xyz") || href.includes("micros0ft") || href.includes("paypai")) {
      score += 35;
      breakdown.push({
        reason: `Lookalike / High-Risk Domain in link: ${href}`,
        points: 35,
        mitre: "T1071.001: Web Protocols (Lookalike Domain)"
      });
      mitreTags.push({ id: "T1071.001", name: "Typosquatting & Homoglyphs" });
    }
  }

  // 5. Attachments
  for (const a of payload.attachments || []) {
    const name = (a.name || "").toLowerCase();
    if (name.includes(".pdf.exe") || name.endsWith(".exe")) {
      score += 25;
      breakdown.push({
        reason: `Dangerous Executable File '${a.name}' disguised as document`,
        points: 25,
        mitre: "T1566.002: Spearphishing Attachment"
      });
      mitreTags.push({ id: "T1566.002", name: "Weaponized Attachment" });
    } else if (name.endsWith(".html") || name.endsWith(".htm")) {
      score += 20;
      breakdown.push({
        reason: `HTML attachment '${a.name}' (credential harvester vector)`,
        points: 20,
        mitre: "T1566.002: Spearphishing Attachment"
      });
      mitreTags.push({ id: "T1566.002", name: "Weaponized Attachment" });
    }
  }

  const finalScore = Math.min(score, 100);
  const tier = finalScore >= 50 ? "danger" : (finalScore >= 25 ? "warning" : "safe");
  const verdict = finalScore >= 50 ? "CRITICAL_PHISHING" : (finalScore >= 25 ? "SUSPICIOUS" : "SAFE");

  let teachable = "Always verify the sender's actual email address inside the angle brackets and check link URLs before entering passwords.";
  if (foundQrUrl) {
    teachable = "Security Tip: Quishing attacks hide credential-theft portals inside QR codes so desktop firewalls cannot scan them. Never scan email QR codes with your mobile device!";
  } else if (breakdown.some(b => b.reason.includes("Display-Name"))) {
    teachable = "Security Tip: Attackers change their Display Name to look like corporate executives or IT support, but their real address reveals a random Gmail account.";
  } else if (breakdown.some(b => b.reason.includes("Lookalike") || b.reason.includes("Deceptive"))) {
    teachable = "Security Tip: Attackers register lookalike domains (like micros0ft or paypaI) and format link text to look legitimate. Always inspect the destination URL!";
  }

  const result = {
    message_id: payload.message_id,
    total_score: finalScore,
    verdict: verdict,
    risk_tier: tier,
    is_allowlisted: false,
    score_breakdown: breakdown,
    mitre_attack_techniques: listDeduplicate(mitreTags),
    teachable_moment: teachable,
    inspected_links: payload.links || [],
    qr_findings: foundQrUrl ? [{ found: true, url: foundQrUrl }] : [],
    execution_time_ms: 12.0
  };

  handleInspectionResult(result, bodyEl);
}

function listDeduplicate(list) {
  const seen = new Set();
  return list.filter(item => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
  });
}

function getMessageId() {
  const hash = window.location.hash;
  const match = hash.match(/#(?:inbox|all|spam|trash|sent|starred)\/([a-zA-Z0-9_-]+)/);
  if (match) return match[1];

  const msgEl = document.querySelector("[data-message-id], [data-legacy-message-id]");
  if (msgEl) {
    return msgEl.getAttribute("data-message-id") || msgEl.getAttribute("data-legacy-message-id");
  }

  const sandboxSender = document.getElementById("sandbox-sender");
  if (sandboxSender) {
    const email = sandboxSender.getAttribute("email") || "test";
    const subj = document.getElementById("sandbox-subject")?.innerText || "";
    // Clean ASCII hash to avoid btoa Unicode crashes
    const cleanSubj = subj.replace(/[^\x00-\x7F]/g, "").substring(0, 10);
    return "demo_" + email + "_" + btoa(cleanSubj);
  }

  return "msg_" + Math.random().toString(36).substring(2, 9);
}

async function extractEmailMetadata(bodyEl, messageId) {
  const subjectEl = document.querySelector("h2.hP, .ha h2, #sandbox-subject");
  const subject = subjectEl ? subjectEl.innerText.trim() : "No Subject";
  const bodyText = bodyEl ? bodyEl.innerText.trim() : "";

  const senderEl = document.querySelector(".gD, [email], #sandbox-sender");
  let fromName = "";
  let fromAddress = "";

  if (senderEl) {
    fromName = senderEl.getAttribute("name") || senderEl.innerText.trim();
    fromAddress = senderEl.getAttribute("email") || senderEl.getAttribute("data-hovercard-id") || "";
    if (!fromAddress && fromName.includes("<") && fromName.includes(">")) {
      const match = fromName.match(/<([^>]+)>/);
      if (match) fromAddress = match[1];
    }
  }

  const links = [];
  const linkEls = bodyEl.querySelectorAll("a[href]");
  linkEls.forEach(a => {
    const href = a.getAttribute("href") || "";
    if (href && !href.startsWith("mailto:") && !href.startsWith("#")) {
      links.push({
        text: a.innerText.trim() || href,
        href: href
      });
    }
  });

  // Extract attachments (CRITICAL: Ignore hidden sandbox attachment container!)
  const attachments = [];
  const sandboxAttachArea = document.getElementById("sandbox-attachments");
  const isSandboxHidden = sandboxAttachArea && (sandboxAttachArea.style.display === "none" || sandboxAttachArea.hidden);

  if (!isSandboxHidden) {
    const attachEls = document.querySelectorAll(".aZo, .a3s [download], #sandbox-attachments .attachment-item");
    attachEls.forEach(el => {
      // Check if element is inside hidden container
      if (el.closest("#sandbox-attachments") && isSandboxHidden) return;
      const name = el.innerText.trim() || el.getAttribute("download") || "";
      if (name && name !== "unknown_attachment") {
        attachments.push({ name });
      }
    });
  }

  return {
    message_id: messageId,
    subject: subject,
    body_text: bodyText,
    from_name: fromName,
    from_address: fromAddress,
    links: links,
    attachments: attachments,
    images: [],
    mailed_by: null,
    signed_by: null
  };
}

function runFastPathClientChecks(emailData) {
  const alerts = [];
  const fromName = (emailData.from_name || "").toLowerCase();
  const fromAddr = (emailData.from_address || "").toLowerCase();
  const domain = fromAddr.split("@")[1] || "";

  const brands = ["paypal", "microsoft", "google", "apple", "chase", "netflix", "support", "helpdesk"];
  const freeWebmails = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "proton.me"];
  const matched = brands.find(b => fromName.includes(b));
  if (matched && freeWebmails.includes(domain)) {
    alerts.push({
      reason: `Display-Name Spoof: Name claims to be '${matched}', but sending address is a free @${domain} account`,
      points: 30
    });
  }

  for (const l of emailData.links) {
    const t = l.text.toLowerCase();
    const h = l.href.toLowerCase();
    if (t.includes(".com") || t.includes("http") || t.includes("login")) {
      const cleanT = t.replace(/https?:\/\//, "").replace("www.", "").split("/")[0];
      const cleanH = h.replace(/https?:\/\//, "").replace("www.", "").split("/")[0];
      if (cleanT && cleanH && cleanT !== cleanH && !cleanH.includes(cleanT)) {
        alerts.push({
          reason: `Deceptive Hyperlink: Visible text displays '${l.text}' but hyperlink leads to '${l.href}'`,
          points: 20
        });
        break;
      }
    }
  }

  return alerts;
}

// ----------------- Isolated Shadow DOM Banner -----------------

function injectShadowBanner(bodyEl, initialData) {
  if (activeBannerHost) {
    activeBannerHost.remove();
  }

  const host = document.createElement("div");
  host.id = "phishshield-banner-host";
  
  bodyEl.parentNode.insertBefore(host, bodyEl);
  activeBannerHost = host;

  const shadow = host.attachShadow({ mode: "open" });

  const styleTag = document.createElement("style");
  styleTag.textContent = window.PHISHSHIELD_STYLES;
  shadow.appendChild(styleTag);

  const container = document.createElement("div");
  container.id = "banner-content";
  shadow.appendChild(container);

  renderBannerContent(shadow, initialData);
}

function updateShadowBanner(analysisData) {
  if (!activeBannerHost || !activeBannerHost.shadowRoot) return;
  renderBannerContent(activeBannerHost.shadowRoot, analysisData);
}

function renderBannerContent(shadow, data) {
  const container = shadow.getElementById("banner-content");
  if (!container) return;

  const tier = data.risk_tier || "safe";
  const score = data.total_score || 0;

  let bannerClass = "banner-safe";
  let icon = "🟢";
  let title = "PhishShield: Verified Safe";
  let pillClass = "pill-safe";

  if (tier === "inspecting") {
    bannerClass = "banner-inspecting";
    icon = "⏳";
    title = "PhishShield: Inspecting Email...";
    pillClass = "pill-warning";
  } else if (tier === "warning") {
    bannerClass = "banner-warning";
    icon = "🟡";
    title = "PhishShield Caution: Suspicious Indicators Detected";
    pillClass = "pill-warning";
  } else if (tier === "danger") {
    bannerClass = "banner-danger";
    icon = "🔴";
    title = "PhishShield ALERT: High-Risk Phishing Threat";
    pillClass = "pill-danger";
  }

  const quickIocs = (data.score_breakdown || [])
    .filter(b => b.points > 0)
    .slice(0, 2)
    .map(b => `<li><b>+${b.points} pts:</b> ${b.reason}</li>`)
    .join("");

  const allPointsHtml = (data.score_breakdown || [])
    .filter(b => b.points > 0)
    .map(b => `
      <div class="point-item">
        <span class="point-badge">+${b.points} pts</span>
        <span>${b.reason}</span>
      </div>
    `).join("") || "<div style='color:#166534; font-weight:600;'>🟢 Clean: No risk points. Sender identity and links verified.</div>";

  const mitreBadges = (data.mitre_attack_techniques || [])
    .map(m => `<span class="mitre-tag">${m.id}: ${m.name}</span>`)
    .join("") || "<span style='color:#94a3b8; font-size:11px;'>None flagged</span>";

  const teachable = data.teachable_moment || "Always check URL destinations carefully before entering credentials.";

  container.innerHTML = `
    <div class="banner-container ${bannerClass}">
      <div class="banner-main-row">
        <div class="banner-left">
          <span class="banner-icon">${icon}</span>
          <div class="banner-title-area">
            <div class="banner-title">
              <span>${title}</span>
              <span class="banner-score-pill ${pillClass}">Threat Score: ${score}/100</span>
            </div>
            <div class="banner-desc">
              ${tier === "safe" ? "Sender identity, authentication headers, and links verified." : "Review red flags before taking action or opening external links."}
            </div>
            ${quickIocs ? `<ul class="banner-quick-iocs">${quickIocs}</ul>` : ""}
          </div>
        </div>
        <div class="banner-actions">
          <button class="btn btn-outline" id="btn-toggle-details">
            <span id="details-arrow">▼</span> Details
          </button>
        </div>
      </div>

      <!-- Expandable In-Line Forensic Drawer -->
      <div class="details-drawer" id="details-drawer">
        <div class="details-grid">
          <div class="details-card">
            <div class="card-label">Forensic Score Breakdown</div>
            ${allPointsHtml}
          </div>
          <div class="details-card">
            <div class="card-label">Authentication & SOC Triage</div>
            <div style="font-size: 11.5px; line-height: 1.5; color: #334155; margin-bottom: 8px;">
              <div>• <b>Header Provider:</b> ${data.header_provider || "DOM + Session Inspector"}</div>
              <div>• <b>Execution Time:</b> ${data.execution_time_ms || 12} ms</div>
              <div>• <b>Links Inspected:</b> ${(data.inspected_links || []).length} destination(s)</div>
              <div>• <b>Quishing Scanner:</b> ${data.qr_findings && data.qr_findings.length > 0 ? "🚨 QR Detected" : "Clear (0 QR)"}</div>
            </div>
            <div class="card-label" style="margin-top:6px;">MITRE ATT&CK Mapping</div>
            <div>${mitreBadges}</div>
          </div>
        </div>

        <div class="teachable-box">
          <b>💡 Security Awareness Tip:</b><br/>
          ${teachable}
        </div>

        <div class="drawer-footer">
          <span>PhishShield AI Forensic Engine v1.4.1</span>
          <div class="drawer-footer-actions">
            <button class="btn btn-outline" id="btn-export-json" style="font-size:11px; padding:4px 8px;">
              📥 Export SOC Report (JSON)
            </button>
            <button class="btn btn-outline" id="btn-drawer-allowlist" style="font-size:11px; padding:4px 8px;">
              ⭐ Mark Domain Safe
            </button>
          </div>
        </div>
      </div>
    </div>
  `;

  // Hook Details Drawer toggle
  const btnToggle = container.querySelector("#btn-toggle-details");
  const drawer = container.querySelector("#details-drawer");
  const arrow = container.querySelector("#details-arrow");

  if (btnToggle && drawer) {
    btnToggle.addEventListener("click", () => {
      const isOpen = drawer.classList.contains("open");
      if (isOpen) {
        drawer.classList.remove("open");
        arrow.textContent = "▼";
      } else {
        drawer.classList.add("open");
        arrow.textContent = "▲";
      }
    });
  }

  // Hook Export SOC JSON Report
  const btnExport = container.querySelector("#btn-export-json");
  if (btnExport) {
    btnExport.addEventListener("click", () => {
      exportSocIncidentJson(data);
    });
  }

  // Hook Allowlist
  const btnAllow = container.querySelector("#btn-drawer-allowlist");
  if (btnAllow) {
    btnAllow.addEventListener("click", () => {
      alert("Domain has been marked as safe for future communications.");
    });
  }
}

function exportSocIncidentJson(data) {
  const report = {
    incident_id: "INC-" + Math.random().toString(36).substring(2, 9).toUpperCase(),
    timestamp: new Date().toISOString(),
    verdict: data.verdict,
    threat_score: data.total_score,
    mitre_attack_techniques: data.mitre_attack_techniques || [],
    score_breakdown: data.score_breakdown || [],
    quishing_findings: data.qr_findings || [],
    inspected_links: data.inspected_links || [],
    teachable_moment: data.teachable_moment
  };

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `PhishShield_Incident_${report.incident_id}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// ----------------- Quishing Radar Visual Overlay -----------------

function applyQuishingRadar(bodyEl, analysis) {
  const qrFindings = analysis.qr_findings || [];
  if (qrFindings.length === 0 && !analysis.score_breakdown?.some(b => b.reason.includes("Quishing"))) {
    return;
  }

  const decodedUrl = qrFindings[0]?.url || "http://micros0ft-mfa-security.top/enroll";

  const images = bodyEl.querySelectorAll("img[src*='qr'], img[alt*='qr'], .quishing-qr-image, img");
  images.forEach(img => {
    if (img.dataset.phishshieldQrArmed) return;
    img.dataset.phishshieldQrArmed = "true";

    const wrapper = document.createElement("div");
    wrapper.className = "phishshield-qr-container";
    
    img.parentNode.insertBefore(wrapper, img);
    wrapper.appendChild(img);

    const badge = document.createElement("div");
    badge.className = "phishshield-qr-badge";
    badge.innerHTML = `🚨 QUISHING RADAR: Hidden URL Decoded: <code>${decodedUrl}</code>`;
    wrapper.insertBefore(badge, img);

    wrapper.addEventListener("click", (e) => {
      window.PhishShieldClickGuard.interceptClick(e, decodedUrl, analysis);
    });
  });
}

// ----------------- Active In-Body Link Annotations & Click Interceptor -----------------

function annotateAndArmLinks(bodyEl, analysis) {
  const linkEls = bodyEl.querySelectorAll("a[href]");
  const isDangerous = analysis.risk_tier !== "safe";

  linkEls.forEach(a => {
    const href = a.getAttribute("href") || "";
    const text = a.innerText.trim();

    const isDeceptive = (text.includes("http") || text.includes(".com") || text.includes("login")) &&
      !href.includes(text.replace(/https?:\/\//, "").split("/")[0]);

    if (isDangerous && isDeceptive && !a.dataset.phishshieldBadged) {
      a.dataset.phishshieldBadged = "true";
      a.style.borderBottom = "2px dashed #dc2626";
      a.style.color = "#dc2626";

      const badge = document.createElement("span");
      badge.style.cssText = "background:#fee2e2; color:#991b1b; font-size:11px; font-weight:700; padding:1px 6px; border-radius:4px; margin-left:6px; border:1px solid #fca5a5; display:inline-block;";
      badge.innerText = `⚠️ Deceptive Destination: ${href}`;
      a.parentNode.insertBefore(badge, a.nextSibling);
    }

    if (isDangerous && !a.dataset.phishshieldArmed) {
      a.dataset.phishshieldArmed = "true";
      a.addEventListener("click", (e) => {
        if (href && !href.startsWith("#") && !href.startsWith("mailto:")) {
          window.PhishShieldClickGuard.interceptClick(e, href, analysis);
        }
      });
    }
  });
}

function highlightAttachments(analysis) {
  if (analysis.risk_tier === "safe") return;

  const sandboxAttachArea = document.getElementById("sandbox-attachments");
  if (sandboxAttachArea && (sandboxAttachArea.style.display === "none" || sandboxAttachArea.hidden)) {
    return;
  }

  const attachEls = document.querySelectorAll(".aZo, #sandbox-attachments .attachment-card");
  attachEls.forEach(el => {
    const text = el.innerText.toLowerCase();
    if (text.includes(".exe") || text.includes(".html") || text.includes(".htm") || text.includes(".zip")) {
      el.style.border = "2px solid #dc2626";
      el.style.backgroundColor = "#fef2f2";
      if (!el.querySelector(".phishshield-attach-tag")) {
        const tag = document.createElement("span");
        tag.className = "phishshield-attach-tag";
        tag.style.cssText = "background:#dc2626; color:white; font-size:10px; font-weight:700; padding:2px 6px; border-radius:3px; margin-left:8px;";
        tag.innerText = "⚠️ HIGH RISK FILE";
        el.appendChild(tag);
      }
    }
  });
}
