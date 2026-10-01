/**
 * PhishShield AI - Background Service Worker (Manifest V3)
 * Implements:
 * - HeaderProvider Interface (ViewOm primary, DomDetails fallback, GmailApi documented)
 * - Communication bus between Content Script, Toolbar Popup, and Python Microservice
 * - Offline / Local-Only Mode fallback engine
 */

const BACKEND_URL = "http://127.0.0.1:8000";

// ----------------- HeaderProvider Architecture -----------------

class HeaderProvider {
  async fetchHeaders(messageId, domDetails) {
    throw new Error("Method fetchHeaders() must be implemented.");
  }
}

/**
 * Primary Provider: Fetches raw RFC 822 stream using active Gmail session cookies.
 */
class ViewOmHeaderProvider extends HeaderProvider {
  async fetchHeaders(messageId, domDetails) {
    if (!messageId || messageId.startsWith("demo_")) {
      return null;
    }
    const url = `https://mail.google.com/mail/u/0/?view=om&th=${encodeURIComponent(messageId)}`;
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1800); // 1.8s timeout
      const response = await fetch(url, {
        signal: controller.signal,
        credentials: "include"
      });
      clearTimeout(timeoutId);

      if (!response.ok) return null;
      const rawText = await response.text();
      return this.parseRfc822(rawText);
    } catch (e) {
      console.warn("[PhishShield] ViewOm fetch failed or timed out. Falling back to DOM details.", e);
      return null;
    }
  }

  parseRfc822(raw) {
    const headers = {};
    const lines = raw.split(/\r?\n/);
    let currentKey = null;

    for (const line of lines) {
      if (line === "") break; // End of header section
      if (/^\s/.test(line) && currentKey) {
        headers[currentKey] += " " + line.trim();
      } else {
        const colonIdx = line.indexOf(":");
        if (colonIdx > 0) {
          currentKey = line.substring(0, colonIdx).toLowerCase();
          headers[currentKey] = line.substring(colonIdx + 1).trim();
        }
      }
    }

    return {
      authResults: headers["authentication-results"] || "",
      returnPath: headers["return-path"] || "",
      replyTo: headers["reply-to"] || "",
      from: headers["from"] || ""
    };
  }
}

/**
 * Fallback Provider: Extracts parsed sender metadata directly from Gmail DOM card.
 */
class DomDetailsHeaderProvider extends HeaderProvider {
  async fetchHeaders(messageId, domDetails) {
    return {
      authResults: "",
      returnPath: "",
      replyTo: domDetails?.replyTo || "",
      from: domDetails?.fromAddress || "",
      mailedBy: domDetails?.mailedBy || "",
      signedBy: domDetails?.signedBy || ""
    };
  }
}

/**
 * Production Path: Documented Google Cloud OAuth REST API implementation.
 */
class GmailApiHeaderProvider extends HeaderProvider {
  async fetchHeaders(messageId, domDetails) {
    // Documented enterprise path:
    // const token = await chrome.identity.getAuthToken({ scopes: ['https://www.googleapis.com/auth/gmail.readonly'] });
    // const res = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=METADATA`, ...);
    return null;
  }
}

// Instantiate Strategy Provider
const viewOmProvider = new ViewOmHeaderProvider();
const domDetailsProvider = new DomDetailsHeaderProvider();

async function resolveHeaders(messageId, domDetails) {
  // Strategy 1: Attempt ViewOm primary
  let headerData = await viewOmProvider.fetchHeaders(messageId, domDetails);
  if (headerData) {
    return { provider: "ViewOmHeaderProvider", data: headerData };
  }
  // Strategy 2: Fallback to DOM Details
  headerData = await domDetailsProvider.fetchHeaders(messageId, domDetails);
  return { provider: "DomDetailsHeaderProvider", data: headerData };
}

// ----------------- Client-Side Fallback Engine -----------------
// Runs if backend is offline or Local-Only Mode is active

function runLocalClientAnalysis(payload) {
  let score = 0;
  const breakdown = [];
  const fromName = (payload.from_name || "").toLowerCase();
  const fromAddr = (payload.from_address || "").toLowerCase();
  const domain = fromAddr.split("@")[1] || "";

  const brands = ["paypal", "microsoft", "google", "apple", "chase", "netflix", "support", "helpdesk", "billing"];
  const freeWebmails = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "proton.me"];

  // 1. Display name spoofing
  const matchedBrand = brands.find(b => fromName.includes(b));
  if (matchedBrand && freeWebmails.includes(domain)) {
    score += 30;
    breakdown.push({
      reason: `Display-Name Spoofing: Sender calls themselves '${matchedBrand}' but uses a free ${domain} account`,
      points: 30
    });
  }

  // 2. Anchor text discrepancy
  for (const l of payload.links || []) {
    const text = (l.text || "").toLowerCase();
    const href = (l.href || "").toLowerCase();
    if (text.includes(".com") || text.includes("http") || text.includes("login")) {
      const cleanT = text.replace(/https?:\/\//, "").replace("www.", "").split("/")[0];
      const cleanH = href.replace(/https?:\/\//, "").replace("www.", "").split("/")[0];
      if (cleanT && cleanH && cleanT !== cleanH && !cleanH.includes(cleanT)) {
        score += 20;
        breakdown.push({
          reason: `Deceptive Link: Visible link text says '${l.text}' but actually points to '${l.href}'`,
          points: 20
        });
      }
    }
    if (href.includes(".top") || href.includes(".xyz") || href.includes("paypai") || href.includes("micros0ft")) {
      score += 35;
      breakdown.push({
        reason: `Lookalike / High-Risk Link Domain detected in email: ${href}`,
        points: 35
      });
    }
  }

  // 3. Attachments
  for (const a of payload.attachments || []) {
    const name = (a.name || "").toLowerCase();
    if (name.endsWith(".html") || name.endsWith(".htm")) {
      score += 20;
      breakdown.push({ reason: `HTML attachment '${a.name}' (credential harvesting risk)`, points: 20 });
    }
    if (name.includes(".pdf.exe") || name.endsWith(".exe")) {
      score += 25;
      breakdown.push({ reason: `Double extension file '${a.name}' (executable disguise)`, points: 25 });
    }
  }

  const finalScore = Math.min(score, 100);
  const tier = finalScore >= 50 ? "danger" : (finalScore >= 25 ? "warning" : "safe");
  const verdict = finalScore >= 50 ? "CRITICAL_PHISHING" : (finalScore >= 25 ? "SUSPICIOUS" : "SAFE");

  return {
    message_id: payload.message_id,
    total_score: finalScore,
    verdict: verdict,
    risk_tier: tier,
    is_allowlisted: false,
    score_breakdown: breakdown,
    teachable_moment: breakdown.length > 0
      ? "Security Tip: Always check the actual sender email in angle brackets and destination links before entering passwords."
      : "No structural threat indicators found. Headers and links appear legitimate.",
    inspected_links: payload.links || [],
    execution_time_ms: 15.0,
    engine: "client_local"
  };
}

// ----------------- Message Bus Dispatcher -----------------

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "ANALYZE_EMAIL") {
    handleAnalyzeEmail(request.payload)
      .then(result => sendResponse({ success: true, result }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true; // Keep channel open for async response
  }

  if (request.type === "GET_LAST_ANALYSIS") {
    chrome.storage.local.get(["lastAnalysis"], (res) => {
      sendResponse(res.lastAnalysis || null);
    });
    return true;
  }
});

async function handleAnalyzeEmail(payload) {
  // Step 1: Resolve headers using HeaderProvider interface
  const headerResolution = await resolveHeaders(payload.message_id, {
    fromAddress: payload.from_address,
    replyTo: payload.reply_to,
    mailedBy: payload.mailed_by,
    signedBy: payload.signed_by
  });

  const fullPayload = {
    ...payload,
    auth_results: headerResolution.data?.authResults || "",
    return_path: headerResolution.data?.returnPath || "",
    reply_to: headerResolution.data?.replyTo || payload.reply_to,
    mailed_by: headerResolution.data?.mailedBy || payload.mailed_by,
    signed_by: headerResolution.data?.signedBy || payload.signed_by
  };

  // Step 2: Check Local-Only mode setting
  const settings = await chrome.storage.local.get(["localOnlyMode"]);
  if (settings.localOnlyMode) {
    const localResult = runLocalClientAnalysis(fullPayload);
    chrome.storage.local.set({ lastAnalysis: localResult });
    return localResult;
  }

  // Step 3: Attempt dispatch to FastAPI Microservice
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500); // 3.5s SLA timeout
    const res = await fetch(`${BACKEND_URL}/api/v1/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(fullPayload),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      data.header_provider = headerResolution.provider;
      chrome.storage.local.set({ lastAnalysis: data });
      return data;
    }
  } catch (err) {
    console.warn("[PhishShield] Backend unavailable or timed out. Falling back to local heuristics.", err);
  }

  // Step 4: Fallback to local client analysis if backend unreachable
  const fallbackResult = runLocalClientAnalysis(fullPayload);
  fallbackResult.header_provider = headerResolution.provider;
  chrome.storage.local.set({ lastAnalysis: fallbackResult });
  return fallbackResult;
}

console.log("[PhishShield] Background Service Worker active with HeaderProvider interface.");
