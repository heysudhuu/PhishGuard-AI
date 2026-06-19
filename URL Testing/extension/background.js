const BACKEND_URL = "http://localhost:8000";

// Handle installation
chrome.runtime.onInstalled.addListener(() => {
    console.log("PhishGuard AI background worker active.");
    chrome.storage.local.set({ 
        whitelisted_domains: [],
        blacklisted_domains: [],
        pg_protection_profile: "balanced"
    });
    syncDomainRules();
});

// Alarm/Timer to sync domain rules every 20 seconds
setInterval(syncDomainRules, 20000);

// Sync rules on startup
syncDomainRules();

// Sync domains from backend periodically
async function syncDomainRules() {
    try {
        const whiteRes = await fetch(`${BACKEND_URL}/api/whitelist`);
        if (whiteRes.ok) {
            const list = await whiteRes.json();
            const domains = list.map(item => item.domain);
            chrome.storage.local.set({ whitelisted_domains: domains });
            console.log("Synced whitelist from backend:", domains);
        }
        
        const blackRes = await fetch(`${BACKEND_URL}/api/blacklist`);
        if (blackRes.ok) {
            const list = await blackRes.json();
            const domains = list.map(item => item.domain);
            chrome.storage.local.set({ blacklisted_domains: domains });
            console.log("Synced blacklist from backend:", domains);
        }
    } catch (err) {
        console.log("Could not sync access rules from backend:", err);
    }
}

// Cache scans in memory to avoid repetitive API requests
const scanCache = {};

// Update Badge UI helper
function updateBadge(tabId, level, score) {
    if (!level) {
        chrome.action.setBadgeText({ tabId, text: "" });
        return;
    }
    
    let badgeText = "";
    let badgeColor = "";
    
    if (level === "dangerous") {
        badgeText = `${score}`;
        badgeColor = "#ef4444"; // Red
    } else if (level === "suspicious") {
        badgeText = `${score}`;
        badgeColor = "#f59e0b"; // Orange/Yellow
    } else {
        badgeText = "OK";
        badgeColor = "#10b981"; // Green
    }
    
    chrome.action.setBadgeText({ tabId, text: badgeText });
    chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
}

// Function to call FastAPI backend
async function scanPage(url, htmlContent) {
    try {
        const headers = {
            "Content-Type": "application/json"
        };

        const response = await fetch(`${BACKEND_URL}/api/scan`, {
            method: "POST",
            headers: headers,
            body: JSON.stringify({
                url: url,
                html_content: htmlContent || ""
            })
        });
        
        if (!response.ok) throw new Error("API scan request failed");
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Error connecting to PhishGuard backend:", error);
        // Return local heuristics estimate if backend offline
        return mockOfflineScan(url);
    }
}

// Local offline heuristics fallback in background script
function mockOfflineScan(url) {
    let score = 20;
    let level = "safe";
    const explanations = ["PhishGuard Engine is offline. Using local heuristics model."];
    
    const urlLower = url.toLowerCase();
    if (urlLower.includes("login") || urlLower.includes("verify") || urlLower.includes("secure")) {
        score = 45;
        level = "suspicious";
        explanations.push("URL contains suspicious keywords (login/verify/secure).");
    }
    if (!url.startsWith("https")) {
        score += 15;
        explanations.push("Connection is insecure (HTTP).");
    }
    if (url.split(".").length > 4) {
        score += 15;
        explanations.push("Excessive subdomains detected.");
    }
    
    if (score > 60) level = "dangerous";
    else if (score > 30) level = "suspicious";

    return {
        id: -1,
        url: url,
        domain: new URL(url).hostname,
        risk_score: score,
        risk_level: level,
        ml_score: score - 10,
        rep_score: 0,
        heuristics_score: score,
        explanations: explanations,
        timestamp: new Date().toISOString(),
        threats: []
    };
}

// Listener for messages from content script or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "page_loaded") {
        const tabId = sender.tab.id;
        const url = request.url;
        
        // Ignore chrome:// and extension pages
        if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
            sendResponse({ status: "ignored" });
            return true;
        }

        // Set state to scanning
        chrome.action.setBadgeText({ tabId, text: "..." });
        chrome.action.setBadgeBackgroundColor({ tabId, color: "#3b82f6" });

        // Trigger API scan
        scanPage(url, request.html).then(result => {
            // Cache scan result
            scanCache[url] = result;
            chrome.storage.local.set({ [url]: result });

            // Broadcast scan completion to active extension UI (e.g., popup)
            chrome.runtime.sendMessage({
                action: "scan_complete",
                url: url,
                result: result
            }).catch(() => {}); // ignore errors when no popup is open

            // Check whitelist, blacklist, and settings storage
            chrome.storage.local.get(["whitelisted_domains", "blacklisted_domains", "pg_protection_profile"], (data) => {
                const whitelisted = data.whitelisted_domains || [];
                const blacklisted = data.blacklisted_domains || [];
                const profile = data.pg_protection_profile || "balanced";
                
                const hostname = new URL(url).hostname.toLowerCase();
                
                // Helper to check wildcard parent segments
                function isMatch(list, host) {
                    if (list.includes(host)) return true;
                    const parts = host.split(".");
                    if (parts.length >= 3) {
                        for (let i = 1; i < parts.length - 1; i++) {
                            const parent = parts.slice(i).join(".");
                            if (list.includes(parent)) return true;
                        }
                    }
                    return false;
                }

                // 1. Whitelisted bypass
                if (isMatch(whitelisted, hostname)) {
                    result.risk_level = "safe";
                    result.risk_score = 0;
                    result.explanations = ["This domain matches your whitelisted trust policies."];
                    updateBadge(tabId, "safe", 0);
                    sendResponse({ status: "whitelisted", result: result });
                    return;
                }

                // 2. Blacklisted forced block
                if (isMatch(blacklisted, hostname)) {
                    result.risk_level = "dangerous";
                    result.risk_score = 100;
                    result.explanations = ["This domain has been explicitly blocked by your custom domain blacklist policies."];
                    updateBadge(tabId, "dangerous", 100);
                    
                    if (profile !== "developer") {
                        chrome.tabs.sendMessage(tabId, { 
                            action: "render_blocking_warning", 
                            result: result 
                        });
                    }
                    sendResponse({ status: "blacklisted", result: result });
                    return;
                }

                // Apply dynamic protection level profiles
                if (profile === "strict") {
                    // Lower threshold and flag brand mismatch
                    if (result.risk_score > 30) {
                        result.risk_level = "dangerous";
                    }
                }

                updateBadge(tabId, result.risk_level, result.risk_score);
                
                // Render warning overlay if dangerous and not Developer Mode
                if (result.risk_level === "dangerous" && profile !== "developer") {
                    chrome.tabs.sendMessage(tabId, { 
                        action: "render_blocking_warning", 
                        result: result 
                    });
                }
                sendResponse({ status: "scanned", result: result });
            });
        }).catch(err => {
            console.error("Scan error:", err);
            chrome.action.setBadgeText({ tabId, text: "ERR" });
            sendResponse({ error: err.message });
        });
        
        return true; // Keep message channel open for async response
    }
    
    if (request.action === "get_cached_scan") {
        const url = request.url;
        // Check memory cache, otherwise look up in local storage
        if (scanCache[url]) {
            sendResponse({ result: scanCache[url] });
        } else {
            chrome.storage.local.get([url], (data) => {
                sendResponse({ result: data[url] || null });
            });
        }
        return true;
    }



    if (request.action === "bypass_warning") {
        const url = request.url;
        const hostname = new URL(url).hostname;
        
        chrome.storage.local.get(["whitelisted_domains"], (data) => {
            const whitelisted = data.whitelisted_domains || [];
            if (!whitelisted.includes(hostname)) {
                whitelisted.push(hostname);
                chrome.storage.local.set({ whitelisted_domains: whitelisted }, () => {
                    // Update cache to reflect safety
                    if (scanCache[url]) {
                        scanCache[url].risk_level = "safe";
                        scanCache[url].risk_score = 0;
                    }
                    
                    // Reset badge in current tab
                    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                        if (tabs[0]) {
                            updateBadge(tabs[0].id, "safe", 0);
                            chrome.tabs.sendMessage(tabs[0].id, { action: "remove_warning" });
                        }
                    });
                    sendResponse({ status: "bypassed" });
                });
            }
        });
        return true;
    }
});
