/**
 * PhishShield AI - Encapsulated Stylesheet for Shadow DOM (v1.4 with Quishing & Urgency Radar)
 */
window.PHISHSHIELD_STYLES = `
  * {
    box-sizing: border-box;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
  }

  .banner-container {
    margin: 12px 0 16px 0;
    border-radius: 8px;
    padding: 14px 18px;
    font-size: 13px;
    line-height: 1.45;
    box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    transition: all 0.25s ease;
  }

  .banner-safe {
    background-color: #f0fdf4;
    border: 1px solid #bbf7d0;
    color: #166534;
  }
  .banner-warning {
    background-color: #fffbeb;
    border: 1px solid #fde68a;
    color: #92400e;
  }
  .banner-danger {
    background-color: #fef2f2;
    border: 1px solid #fecaca;
    color: #991b1b;
  }
  .banner-inspecting {
    background-color: #f8fafc;
    border: 1px solid #e2e8f0;
    color: #475569;
  }

  .banner-main-row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
  }

  .banner-left {
    display: flex;
    gap: 12px;
    align-items: flex-start;
  }

  .banner-icon {
    font-size: 22px;
    line-height: 1;
    margin-top: 1px;
  }

  .banner-title-area {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .banner-title {
    font-weight: 700;
    font-size: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .banner-score-pill {
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.2px;
  }
  .pill-safe { background: #dcfce7; color: #15803d; border: 1px solid #86efac; }
  .pill-warning { background: #fef3c7; color: #b45309; border: 1px solid #fcd34d; }
  .pill-danger { background: #fee2e2; color: #b91c1c; border: 1px solid #fca5a5; }

  .banner-desc {
    font-size: 12.5px;
    color: inherit;
    opacity: 0.9;
  }

  .banner-quick-iocs {
    margin-top: 6px;
    padding-left: 18px;
    font-size: 12px;
  }
  .banner-quick-iocs li {
    margin-bottom: 2px;
  }

  .banner-actions {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-shrink: 0;
  }

  .btn {
    border: none;
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s ease;
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }
  .btn-outline {
    background: #ffffff;
    border: 1px solid currentColor;
    color: inherit;
    box-shadow: 0 1px 2px rgba(0,0,0,0.05);
  }
  .btn-outline:hover {
    background: rgba(0,0,0,0.04);
  }

  /* Expandable Details Drawer */
  .details-drawer {
    margin-top: 14px;
    padding-top: 14px;
    border-top: 1px solid rgba(0,0,0,0.12);
    display: none;
    animation: fadeIn 0.2s ease-in-out;
  }
  .details-drawer.open {
    display: block;
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-4px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .details-grid {
    display: grid;
    grid-template-columns: 1.2fr 0.8fr;
    gap: 12px;
    margin-bottom: 12px;
  }

  .details-card {
    background: #ffffff;
    border-radius: 6px;
    border: 1px solid rgba(0,0,0,0.1);
    padding: 10px 12px;
    font-size: 12px;
  }

  .card-label {
    font-weight: 700;
    font-size: 10.5px;
    text-transform: uppercase;
    color: #64748b;
    margin-bottom: 6px;
    letter-spacing: 0.5px;
  }

  .point-item {
    display: flex;
    align-items: flex-start;
    gap: 6px;
    margin-bottom: 5px;
    font-size: 11.5px;
  }

  .point-badge {
    background: #fee2e2;
    color: #991b1b;
    font-weight: 700;
    padding: 1px 5px;
    border-radius: 4px;
    font-size: 10px;
    white-space: nowrap;
  }

  .mitre-tag {
    font-family: monospace;
    font-size: 9.5px;
    background: #f1f5f9;
    color: #475569;
    padding: 2px 5px;
    border-radius: 3px;
    border: 1px solid #cbd5e1;
    display: inline-block;
    margin-right: 4px;
    margin-bottom: 4px;
  }

  .teachable-box {
    background: #eff6ff;
    border-left: 3px solid #3b82f6;
    border-radius: 0 6px 6px 0;
    padding: 10px 12px;
    font-size: 12px;
    color: #1e3a8a;
    line-height: 1.45;
    margin-top: 10px;
  }

  .drawer-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 12px;
    padding-top: 8px;
    border-top: 1px dashed rgba(0,0,0,0.1);
    font-size: 11px;
    color: #64748b;
    flex-wrap: wrap;
    gap: 8px;
  }

  .drawer-footer-actions {
    display: flex;
    gap: 8px;
  }

  /* Quishing Radar Visual Overlay on Images */
  .phishshield-qr-container {
    position: relative;
    display: inline-block;
    border: 3px solid #dc2626 !important;
    border-radius: 8px;
    box-shadow: 0 0 15px rgba(220, 38, 38, 0.45);
    margin: 10px 0;
    overflow: hidden;
  }

  .phishshield-qr-badge {
    background: #dc2626;
    color: white;
    font-size: 11px;
    font-weight: 700;
    padding: 5px 10px;
    text-align: center;
    letter-spacing: 0.3px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
  }

  /* Safe Click Guard Modal */
  .modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background: rgba(15, 23, 42, 0.65);
    backdrop-filter: blur(3px);
    z-index: 99999999;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .modal-card {
    background: #ffffff;
    border-radius: 12px;
    width: 500px;
    max-width: 92vw;
    padding: 22px;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.25), 0 10px 10px -5px rgba(0, 0, 0, 0.08);
    border: 1px solid #e2e8f0;
  }

  .modal-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 12px;
  }

  .modal-title {
    font-size: 16px;
    font-weight: 700;
    color: #991b1b;
  }

  .modal-body {
    font-size: 12.5px;
    color: #334155;
    line-height: 1.5;
  }

  .url-preview {
    background: #f1f5f9;
    padding: 8px 12px;
    border-radius: 6px;
    font-family: monospace;
    font-size: 11.5px;
    word-break: break-all;
    margin: 10px 0;
    border: 1px solid #cbd5e1;
    color: #0f172a;
  }

  .modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin-top: 18px;
  }

  .btn-abort {
    background: #dc2626;
    color: white;
    padding: 8px 14px;
    font-size: 12.5px;
    border-radius: 6px;
    font-weight: 600;
  }
  .btn-abort:hover {
    background: #b91c1c;
  }

  .btn-proceed {
    background: transparent;
    color: #64748b;
    padding: 8px 12px;
    font-size: 12px;
    text-decoration: underline;
  }
  .btn-proceed:hover {
    color: #0f172a;
  }
`;
