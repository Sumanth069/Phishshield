/**
 * PhishShield AI - Safe Click Guard
 * Active link interceptor that prevents immediate navigation to flagged URLs,
 * displays an explanatory security modal, and delivers teachable moments.
 */

window.PhishShieldClickGuard = {
  activeModalHost: null,

  interceptClick(event, linkUrl, analysisData) {
    event.preventDefault();
    event.stopPropagation();

    this.showModal(linkUrl, analysisData);
  },

  showModal(targetUrl, analysis) {
    if (this.activeModalHost) {
      this.activeModalHost.remove();
    }

    const host = document.createElement("div");
    host.id = "phishshield-modal-host";
    document.body.appendChild(host);
    this.activeModalHost = host;

    const shadow = host.attachShadow({ mode: "open" });

    const styleTag = document.createElement("style");
    styleTag.textContent = window.PHISHSHIELD_STYLES;
    shadow.appendChild(styleTag);

    const breakdownItems = (analysis?.score_breakdown || [])
      .map(b => `<li><b>+${b.points} pts:</b> ${b.reason}</li>`)
      .join("");

    const teachable = analysis?.teachable_moment || "Always check URL destinations carefully before entering credentials.";

    const modalHtml = `
      <div class="modal-overlay">
        <div class="modal-card">
          <div class="modal-header">
            <span style="font-size: 24px;">⚠️</span>
            <div class="modal-title">PhishShield: Suspicious Link Intercepted</div>
          </div>
          <div class="modal-body">
            <p>You attempted to open an external link from an email flagged as <b>${analysis?.verdict || "HIGH RISK"}</b>.</p>
            
            <div class="url-preview">${escapeHtml(targetUrl)}</div>
            
            ${breakdownItems ? `<ul class="banner-iocs">${breakdownItems}</ul>` : ""}

            <div class="teachable-card">
              <b>💡 Awareness Tip:</b><br/>
              ${escapeHtml(teachable)}
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn btn-proceed" id="btn-proceed">Proceed at own risk</button>
            <button class="btn btn-abort" id="btn-abort">🛡️ Abort Navigation (Recommended)</button>
          </div>
        </div>
      </div>
    `;

    const container = document.createElement("div");
    container.innerHTML = modalHtml;
    shadow.appendChild(container);

    shadow.getElementById("btn-abort").addEventListener("click", () => {
      host.remove();
      this.activeModalHost = null;
      console.log("[PhishShield] User safely aborted navigation to:", targetUrl);
    });

    shadow.getElementById("btn-proceed").addEventListener("click", () => {
      host.remove();
      this.activeModalHost = null;
      console.warn("[PhishShield] User elected to proceed to:", targetUrl);
      window.open(targetUrl, "_blank", "noopener,noreferrer");
    });
  }
};

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
