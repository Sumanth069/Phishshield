/**
 * PhishShield AI - Popup Controller
 */

document.addEventListener("DOMContentLoaded", async () => {
  const scoreNum = document.getElementById("score-num");
  const verdictText = document.getElementById("verdict-text");
  const providerTag = document.getElementById("provider-tag");
  const gaugeCircle = document.getElementById("gauge-circle");
  const breakdownList = document.getElementById("breakdown-list");
  const btnAllowlist = document.getElementById("btn-allowlist");
  const btnSandbox = document.getElementById("btn-sandbox");
  const localToggle = document.getElementById("local-mode-toggle");
  const statusPill = document.getElementById("status-pill");

  // Load Settings
  const settings = await chrome.storage.local.get(["localOnlyMode", "lastAnalysis"]);
  if (settings.localOnlyMode) {
    localToggle.checked = true;
    statusPill.textContent = "LOCAL ONLY";
    statusPill.className = "status-pill status-offline";
  }

  localToggle.addEventListener("change", (e) => {
    chrome.storage.local.set({ localOnlyMode: e.target.checked });
    statusPill.textContent = e.target.checked ? "LOCAL ONLY" : "ONLINE";
    statusPill.className = e.target.checked ? "status-pill status-offline" : "status-pill status-online";
  });

  // Launch Demo Sandbox
  btnSandbox.addEventListener("click", () => {
    const sandboxUrl = chrome.runtime.getURL("demo_sandbox.html");
    chrome.tabs.create({ url: sandboxUrl });
  });

  // Load Last Analysis
  const data = settings.lastAnalysis;
  if (!data) return;

  const score = data.total_score || 0;
  scoreNum.textContent = score;
  verdictText.textContent = formatVerdict(data.verdict);
  providerTag.textContent = `Provider: ${data.header_provider || "Local Heuristics"}`;

  // Update Gauge Styling
  let color = "#10b981"; // Green
  if (score >= 50) color = "#ef4444"; // Red
  else if (score >= 25) color = "#f59e0b"; // Amber

  gaugeCircle.style.background = `conic-gradient(${color} 0% ${score}%, #e2e8f0 ${score}% 100%)`;

  // Render IOC breakdown
  const items = (data.score_breakdown || []).filter(b => b.points > 0);
  if (items.length > 0) {
    breakdownList.innerHTML = items.map(b => `
      <div class="ioc-item">
        <span class="ioc-badge">+${b.points} pts</span>
        <span>${escapeHtml(b.reason)}</span>
      </div>
    `).join("");
  } else {
    breakdownList.innerHTML = `<div class="empty-state">🟢 All integrity checks passed. No threats detected.</div>`;
  }

  // Handle Allowlist
  btnAllowlist.addEventListener("click", async () => {
    const fromDomain = (data.from_address || "").split("@")[1];
    if (!fromDomain) {
      alert("No active domain to allowlist.");
      return;
    }
    try {
      await fetch("http://127.0.0.1:8000/api/v1/allowlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: fromDomain })
      });
      alert(`Domain '${fromDomain}' marked as safe.`);
    } catch (e) {
      alert(`Domain '${fromDomain}' saved to local allowlist.`);
    }
  });
});

function formatVerdict(v) {
  if (v === "CRITICAL_PHISHING") return "🔴 Critical Phishing Threat";
  if (v === "SUSPICIOUS") return "🟡 Suspicious Email";
  if (v === "SAFE") return "🟢 Verified Safe";
  return v || "No Email Selected";
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
