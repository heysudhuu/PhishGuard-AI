// Content Script for PhishGuard AI
const tabUrl = window.location.href;

// 1. Send DOM information to background scanner on load
function reportPageDetails() {
    // Ignore internal chrome extensions
    if (tabUrl.startsWith("chrome://") || tabUrl.startsWith("chrome-extension://")) {
        return;
    }
    
    // Send message to background service worker
    chrome.runtime.sendMessage({
        action: "page_loaded",
        url: tabUrl,
        html: document.documentElement.outerHTML
    }, (response) => {
        if (chrome.runtime.lastError) {
            console.log("Background connection not active yet.");
            return;
        }
        if (response && response.status === "scanned") {
            console.log("PhishGuard AI Scan Complete:", response.result);
        }
    });
}

// 2. Event Listeners for Credential Leak Protection
function setupCredentialProtection() {
    let alerted = false;
    
    document.addEventListener("focusin", (e) => {
        if (e.target && e.target.type === "password") {
            if (alerted) return;
            
            // Check if site is risky
            chrome.runtime.sendMessage({ action: "get_cached_scan", url: tabUrl }, (response) => {
                if (response && response.result) {
                    const res = response.result;
                    if (res.risk_level === "dangerous" || res.risk_level === "suspicious") {
                        showPasswordWarningBanner(res.risk_level, res.risk_score);
                        alerted = true;
                    }
                }
            });
        }
    });

    // Intercept form submissions on risky sites
    document.addEventListener("submit", (e) => {
        // Find if submitting form contains passwords
        const hasPasswordInput = e.target.querySelector("input[type='password']");
        if (hasPasswordInput) {
            // Check risk status
            chrome.runtime.sendMessage({ action: "get_cached_scan", url: tabUrl }, (response) => {
                if (response && response.result) {
                    const res = response.result;
                    if (res.risk_level === "dangerous") {
                        // Prevent actual submission
                        e.preventDefault();
                        e.stopPropagation();
                        
                        showCredentialSubmissionBlocker(e.target);
                    }
                }
            });
        }
    }, true); // Capture phase to intercept reliably
}

// Injected styling helper
function injectStyle(cssText) {
    const style = document.createElement("style");
    style.id = "phishguard-injected-style";
    style.textContent = cssText;
    document.head.appendChild(style);
}

// 3. Render a Warning banner above password fields
function showPasswordWarningBanner(riskLevel, score) {
    if (document.getElementById("phishguard-password-banner")) return;
    
    injectStyle(`
        #phishguard-password-banner {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(15, 23, 42, 0.95);
            color: #f3f4f6;
            border-left: 4px solid ${riskLevel === "dangerous" ? "#ef4444" : "#f59e0b"};
            box-shadow: 0 10px 30px rgba(0,0,0,0.5), 0 0 1px rgba(255,255,255,0.2);
            padding: 16px;
            border-radius: 8px;
            z-index: 2147483645;
            width: 380px;
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            animation: slideInBanner 0.4s cubic-bezier(0.16, 1, 0.3, 1);
            backdrop-filter: blur(8px);
        }
        @keyframes slideInBanner {
            from { transform: translateY(50px) scale(0.9); opacity: 0; }
            to { transform: translateY(0) scale(1); opacity: 1; }
        }
        .pg-banner-header {
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 700;
            margin-bottom: 6px;
            font-size: 15px;
            color: ${riskLevel === "dangerous" ? "#ef4444" : "#f59e0b"};
        }
        .pg-banner-body {
            font-size: 13px;
            line-height: 1.4;
            color: #9ca3af;
            margin-bottom: 12px;
        }
        .pg-banner-actions {
            display: flex;
            justify-content: flex-end;
            gap: 8px;
        }
        .pg-btn-sm {
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            border: none;
            font-family: inherit;
        }
        .pg-btn-sm.pg-primary {
            background-color: ${riskLevel === "dangerous" ? "#ef4444" : "#f59e0b"};
            color: white;
        }
        .pg-btn-sm.pg-secondary {
            background-color: #334155;
            color: #f3f4f6;
        }
    `);
    
    const banner = document.createElement("div");
    banner.id = "phishguard-password-banner";
    banner.innerHTML = `
        <div class="pg-banner-header">
            <span style="font-size: 18px;">⚠️</span>
            <span>Credential Risk Alert (${score}% Risk)</span>
        </div>
        <div class="pg-banner-body">
            PhishGuard AI has marked this domain as <strong>${riskLevel}</strong>. 
            Entering passwords here is highly risky as it resembles a phishing target.
        </div>
        <div class="pg-banner-actions">
            <button class="pg-btn-sm pg-secondary" id="pg-banner-close">Dismiss</button>
            <button class="pg-btn-sm pg-primary" id="pg-banner-leave">Leave Site</button>
        </div>
    `;
    
    document.body.appendChild(banner);
    
    document.getElementById("pg-banner-close").addEventListener("click", () => {
        banner.remove();
    });
    
    document.getElementById("pg-banner-leave").addEventListener("click", () => {
        window.location.href = "https://www.google.com";
    });
}

// 4. Force full Credential Submission Block Modal
function showCredentialSubmissionBlocker(formElement) {
    if (document.getElementById("phishguard-submission-modal")) return;
    
    injectStyle(`
        #phishguard-submission-modal {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(8, 10, 16, 0.9);
            z-index: 2147483647;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Outfit', sans-serif;
            color: #f3f4f6;
            backdrop-filter: blur(10px);
        }
        .pg-modal-card {
            background: #0f172a;
            border: 1px solid #ef4444;
            padding: 30px;
            border-radius: 12px;
            width: 450px;
            max-width: 90%;
            text-align: center;
            box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.25);
        }
        .pg-modal-icon {
            font-size: 50px;
            color: #ef4444;
            margin-bottom: 16px;
        }
        .pg-modal-title {
            font-size: 22px;
            font-weight: 700;
            margin-bottom: 10px;
        }
        .pg-modal-body {
            font-size: 14px;
            color: #9ca3af;
            line-height: 1.5;
            margin-bottom: 24px;
        }
        .pg-modal-buttons {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .pg-btn-lg {
            padding: 12px 20px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            border: none;
            font-family: inherit;
            transition: all 0.2s;
        }
        .pg-btn-lg.pg-primary {
            background: #ef4444;
            color: white;
        }
        .pg-btn-lg.pg-primary:hover {
            background: #dc2626;
        }
        .pg-btn-lg.pg-secondary {
            background: #1e293b;
            color: #f3f4f6;
        }
        .pg-btn-lg.pg-secondary:hover {
            background: #334155;
        }
    `);
    
    const modal = document.createElement("div");
    modal.id = "phishguard-submission-modal";
    modal.innerHTML = `
        <div class="pg-modal-card">
            <div class="pg-modal-icon">🔒🛑</div>
            <div class="pg-modal-title">Credential Theft Blocked</div>
            <div class="pg-modal-body">
                PhishGuard AI blocked this website from submitting your password. 
                This domain is strongly suspected of brand spoofing and phishing.
            </div>
            <div class="pg-modal-buttons">
                <button class="pg-btn-lg pg-primary" id="pg-submit-leave">Get Me to Safety</button>
                <button class="pg-btn-lg pg-secondary" id="pg-submit-bypass">Ignore and Submit Anyway</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    document.getElementById("pg-submit-leave").addEventListener("click", () => {
        window.location.href = "https://www.google.com";
    });
    
    document.getElementById("pg-submit-bypass").addEventListener("click", () => {
        modal.remove();
        // Trigger actual submission bypassing content listener
        formElement.submit();
    });
}

// 5. Injected Full-Page Warning Overlay (Main phishing block screen)
function renderBlockingWarning(result) {
    if (document.getElementById("phishguard-warning-overlay")) return;
    
    injectStyle(`
        #phishguard-warning-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: linear-gradient(135deg, #090b11 0%, #150808 100%);
            z-index: 2147483646;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
            color: #f3f4f6;
            padding: 20px;
        }
        .warning-card {
            background: rgba(17, 24, 39, 0.7);
            border: 1px solid rgba(239, 68, 68, 0.2);
            padding: 40px;
            border-radius: 16px;
            width: 650px;
            max-width: 100%;
            box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
        }
        .warning-icon {
            font-size: 60px;
            color: #ef4444;
            margin-bottom: 20px;
            text-align: center;
        }
        .warning-title {
            font-size: 28px;
            font-weight: 800;
            margin-bottom: 12px;
            text-align: center;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #ef4444, #f59e0b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .warning-subtitle {
            font-size: 15px;
            color: #e5e7eb;
            text-align: center;
            margin-bottom: 28px;
            line-height: 1.5;
        }
        .warning-domain-indicator {
            background: #1f2937;
            padding: 10px 14px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 14px;
            text-align: center;
            margin-bottom: 24px;
            border: 1px solid rgba(255,255,255,0.05);
            word-break: break-all;
        }
        .warning-explanations-title {
            font-size: 12px;
            font-weight: 600;
            color: #9ca3af;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }
        .warning-explanations {
            display: flex;
            flex-direction: column;
            gap: 10px;
            margin-bottom: 30px;
            text-align: left;
        }
        .warning-exp-item {
            display: flex;
            gap: 10px;
            font-size: 14px;
            line-height: 1.4;
            color: #d1d5db;
        }
        .warning-exp-item span.bullet {
            color: #ef4444;
            font-weight: bold;
        }
        .warning-footer-actions {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .warning-btn {
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 700;
            font-size: 14px;
            cursor: pointer;
            border: none;
            font-family: inherit;
            transition: all 0.2s;
        }
        .warning-btn.btn-danger {
            background: #ef4444;
            color: white;
            box-shadow: 0 4px 14px rgba(239, 68, 68, 0.4);
        }
        .warning-btn.btn-danger:hover {
            background: #dc2626;
            transform: translateY(-1px);
        }
        .warning-link-bypass {
            color: #9ca3af;
            text-decoration: underline;
            font-size: 13px;
            cursor: pointer;
            background: none;
            border: none;
            font-family: inherit;
        }
        .warning-link-bypass:hover {
            color: #f3f4f6;
        }
    `);
    
    // Disable scrolling on background body
    document.body.style.overflow = "hidden";
    
    const overlay = document.createElement("div");
    overlay.id = "phishguard-warning-overlay";
    
    let bulletList = "";
    result.explanations.forEach(exp => {
        bulletList += `
            <div class="warning-exp-item">
                <span class="bullet">✓</span>
                <span>${exp}</span>
            </div>
        `;
    });

    overlay.innerHTML = `
        <div class="warning-card">
            <div class="warning-icon">🛡️</div>
            <div class="warning-title">Deceptive Site Blocked</div>
            <div class="warning-subtitle">
                PhishGuard AI has blocked access to this page because it matches severe phishing signatures and risk indicators.
            </div>
            
            <div class="warning-domain-indicator">${result.url}</div>
            
            <div class="warning-explanations-title">Engine Risk Explanations (${result.risk_score}% Risk Score)</div>
            <div class="warning-explanations">
                ${bulletList}
            </div>
            
            <div class="warning-footer-actions">
                <button class="warning-link-bypass" id="pg-btn-bypass">Proceed anyway (unsafe)</button>
                <button class="warning-btn btn-danger" id="pg-btn-back">Go Back to Safety</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(overlay);
    
    document.getElementById("pg-btn-back").addEventListener("click", () => {
        window.location.href = "https://www.google.com";
    });
    
    document.getElementById("pg-btn-bypass").addEventListener("click", () => {
        chrome.runtime.sendMessage({
            action: "bypass_warning",
            url: tabUrl
        }, (response) => {
            if (response && response.status === "bypassed") {
                removeWarning();
            }
        });
    });
}

function removeWarning() {
    const overlay = document.getElementById("phishguard-warning-overlay");
    if (overlay) {
        overlay.remove();
        document.body.style.overflow = ""; // restore scrolling
    }
}

// 6. Message Listener to toggle warning overlay
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "render_blocking_warning") {
        renderBlockingWarning(request.result);
        sendResponse({ status: "overlay_rendered" });
    } else if (request.action === "remove_warning") {
        removeWarning();
        sendResponse({ status: "overlay_removed" });
    }
    return true;
});

// Run scans and setup protections
reportPageDetails();
setupCredentialProtection();
