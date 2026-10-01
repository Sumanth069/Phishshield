/**
 * PhishShield AI - Demo Sandbox Controller
 * External script compliant with Chrome Manifest V3 Content Security Policy (CSP).
 * Strictly avoids inline scripts or inline event handlers.
 */

console.log("[PhishShield Sandbox] Sandbox controller initialized.");

const scenarios = {
  1: {
    id: "demo_safe_github",
    subject: "[Security Alert] Personal Access Token Created",
    name: "GitHub Security",
    email: "notifications@github.com",
    avatar: "GH",
    body: `
      <p>Hi Developer,</p><br/>
      <p>A new personal access token (classic) was recently generated on your GitHub account with <code>repo</code> and <code>workflow</code> scopes.</p><br/>
      <p>If you made this change, no action is required.</p>
      <p>If you did not generate this token, please visit your account settings to revoke it immediately:</p><br/>
      <p><a href="https://github.com/settings/tokens">https://github.com/settings/tokens</a></p><br/>
      <p>Thanks,<br/>The GitHub Team</p>
    `,
    attachments: []
  },
  2: {
    id: "demo_bec_spoof",
    subject: "URGENT: Quick confidential task needed before board meeting",
    name: "John Smith (CEO)",
    email: "john.smith.corp.exec@gmail.com",
    avatar: "JS",
    body: `
      <p>Hi team,</p><br/>
      <p>I am currently tied up in an off-site confidential conference call with our legal team and cannot access our corporate banking portal.</p><br/>
      <p>I need you to urgently process 4 digital gift cards for client presentations this afternoon. Please reply immediately to confirm receipt so I can send the purchase link.</p><br/>
      <p>Regards,<br/>John Smith<br/>Chief Executive Officer</p>
    `,
    attachments: []
  },
  3: {
    id: "demo_phish_m365",
    subject: "CRITICAL: Microsoft 365 Password Expiration Notice",
    name: "Microsoft 365 IT Helpdesk",
    email: "support-update-9481@gmail.com",
    avatar: "MS",
    body: `
      <p>Dear Corporate User,</p><br/>
      <p>Your Microsoft 365 enterprise password is scheduled to expire in <b>2 hours</b>. Failure to update your password will result in immediate suspension of corporate email and OneDrive access.</p><br/>
      <p>Click below to retain your current password and verify your session credentials:</p><br/>
      <p><a href="http://micros0ft-login.top/verify-account">https://login.microsoftonline.com/common/oauth2/v2.0/authorize</a></p><br/>
      <p>Please also review the attached account statement.</p><br/>
      <p>IT Department Administrator</p>
    `,
    attachments: ["Invoice_Statement.pdf.exe"]
  },
  4: {
    id: "demo_quishing_mfa",
    subject: "[URGENT] Microsoft Authenticator MFA Re-enrollment Required",
    name: "Microsoft Security & Identity",
    email: "mfa-enrollment-service@gmail.com",
    avatar: "MFA",
    body: `
      <p>Dear Corporate User,</p><br/>
      <p>Due to enterprise zero-trust security updates, all employees are required to re-enroll their Multi-Factor Authentication (MFA) within <b>2 hours</b> to avoid account lock-out.</p><br/>
      <p>Please open the camera app on your personal mobile device and <b>scan the QR code below</b> to complete your session verification:</p><br/>
      <div style="text-align:center; padding:16px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; display:inline-block; margin: 10px 0;">
        <img src="icons/quishing_qr.png" alt="Microsoft MFA Enrollment QR Code" class="quishing-qr-image" style="width:190px; height:190px; display:block; cursor:pointer;" />
        <span style="font-size:11.5px; color:#64748b; margin-top:8px; display:block;">Scan with mobile camera or Authenticator app</span>
      </div><br/><br/>
      <p>If you are unable to scan this code from your mobile device, please report to the IT Helpdesk immediately.</p><br/>
      <p>Microsoft Enterprise Security Operations</p>
    `,
    attachments: []
  }
};

function switchScenario(scenNum) {
  console.log("[PhishShield Sandbox] Switching to Scenario", scenNum);
  const scen = scenarios[scenNum];
  if (!scen) return;

  // Update button active state
  document.querySelectorAll(".scenario-btn").forEach(b => b.classList.remove("active"));
  const targetBtn = document.getElementById("btn-scen-" + scenNum);
  if (targetBtn) targetBtn.classList.add("active");

  // Remove any existing banner or badge artifacts
  const existingHost = document.getElementById("phishshield-banner-host");
  if (existingHost) existingHost.remove();

  document.querySelectorAll("[data-phishshield-badged], [data-phishshield-armed], [data-phishshield-qr-armed]").forEach(el => {
    delete el.dataset.phishshieldBadged;
    delete el.dataset.phishshieldArmed;
    delete el.dataset.phishshieldQrArmed;
  });

  // Update Subject
  const subjEl = document.getElementById("sandbox-subject");
  if (subjEl) subjEl.innerText = scen.subject;

  // Update Sender
  const nameEl = document.getElementById("sandbox-sender-name");
  if (nameEl) nameEl.innerText = scen.name;

  const senderEl = document.getElementById("sandbox-sender");
  if (senderEl) {
    senderEl.innerText = `<${scen.email}>`;
    senderEl.setAttribute("email", scen.email);
    senderEl.setAttribute("name", scen.name);
  }

  // Update Avatar
  const avatarEl = document.getElementById("sandbox-avatar");
  if (avatarEl) avatarEl.innerText = scen.avatar;

  // Update Email Body
  const bodyEl = document.getElementById("sandbox-email-body");
  if (bodyEl) bodyEl.innerHTML = scen.body;

  // Update Attachments
  const attachArea = document.getElementById("sandbox-attachments");
  const attachItem = document.querySelector("#sandbox-attachment-name .attachment-item");

  if (scen.attachments && scen.attachments.length > 0) {
    if (attachArea) attachArea.style.display = "block";
    if (attachItem) attachItem.innerText = scen.attachments[0];
  } else {
    if (attachArea) attachArea.style.display = "none";
    if (attachItem) attachItem.innerText = "";
  }

  // Trigger content script evaluation
  if (window.PhishShield && window.PhishShield.inspectEmail) {
    window.PhishShield.inspectEmail(true);
  }
}

// Ensure listeners are bound once DOM is ready
document.addEventListener("DOMContentLoaded", () => {
  console.log("[PhishShield Sandbox] Binding scenario button listeners...");
  for (let i = 1; i <= 4; i++) {
    const btn = document.getElementById("btn-scen-" + i);
    if (btn) {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        switchScenario(i);
      });
    }
  }

  // Auto-load Scenario 1
  setTimeout(() => switchScenario(1), 200);
});
