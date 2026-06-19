document.addEventListener("DOMContentLoaded", () => {
    const riskScore = document.getElementById("risk-score");
    const riskBadge = document.getElementById("risk-level-badge");
    const domainDisplay = document.getElementById("domain-display");
    const explanationsContainer = document.getElementById("explanations-container");
    const btnWhitelist = document.getElementById("btn-whitelist");
    const btnDashboard = document.getElementById("btn-dashboard");
    const openDashboard = document.getElementById("open-dashboard");
    const gaugeOuter = document.querySelector(".gauge-outer");

    let currentTabUrl = "";

    // 1. Get current active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs[0]) return;
        
        const tab = tabs[0];
        currentTabUrl = tab.url;
        
        // Handle browser settings pages
        if (currentTabUrl.startsWith("chrome://") || currentTabUrl.startsWith("chrome-extension://")) {
            renderSystemPage();
            return;
        }

        // Get hostname
        try {
            const domain = new URL(currentTabUrl).hostname;
            domainDisplay.textContent = domain;
        } catch (e) {
            domainDisplay.textContent = currentTabUrl;
        }

        // Request cached scan result from background
        chrome.runtime.sendMessage({
            action: "get_cached_scan",
            url: currentTabUrl
        }, (response) => {
            if (response && response.result) {
                renderScanResult(response.result);
            } else {
                renderScanningState();
            }
        });
    });

    // Populate UI elements from scan result
    function renderScanResult(result) {
        const score = result.risk_score;
        const level = result.risk_level;
        
        // Update Score and Gauge
        riskScore.textContent = `${score}%`;
        gaugeOuter.style.setProperty("--percentage", `${score}%`);
        
        // Set gauge color class
        gaugeOuter.className = "gauge-outer"; // reset classes
        gaugeOuter.classList.add(`gauge-${level}`);
        
        // Update Risk Badge
        riskBadge.textContent = level;
        riskBadge.className = "risk-badge"; // reset classes
        riskBadge.classList.add(level);

        // Populate Explanations
        explanationsContainer.innerHTML = "";
        if (result.explanations && result.explanations.length > 0) {
            result.explanations.forEach(exp => {
                const item = document.createElement("div");
                item.className = `exp-item exp-${level}`;
                
                const bullet = level === "dangerous" ? "🔴" : 
                               level === "suspicious" ? "🟡" : "🟢";
                               
                item.innerHTML = `
                    <span class="exp-bullet">${bullet}</span>
                    <span>${exp}</span>
                `;
                explanationsContainer.appendChild(item);
            });
        } else {
            explanationsContainer.innerHTML = `
                <div class="exp-item exp-safe">
                    <span class="exp-bullet">🟢</span>
                    <span>No security anomalies detected on this page.</span>
                </div>
            `;
        }

        // Whitelist button state
        chrome.storage.local.get(["whitelisted_domains"], (data) => {
            const whitelisted = data.whitelisted_domains || [];
            const hostname = new URL(currentTabUrl).hostname;
            if (whitelisted.includes(hostname)) {
                btnWhitelist.textContent = "Domain Trusted";
                btnWhitelist.disabled = true;
                
                // Show safe status because bypassed
                riskScore.textContent = "0%";
                gaugeOuter.style.setProperty("--percentage", "0%");
                gaugeOuter.className = "gauge-outer gauge-safe";
                riskBadge.textContent = "trusted";
                riskBadge.className = "risk-badge safe";
            } else {
                btnWhitelist.textContent = "Trust Domain";
                btnWhitelist.disabled = false;
            }
        });
    }

    function renderScanningState() {
        riskScore.textContent = "...";
        riskBadge.textContent = "Scanning";
        riskBadge.className = "risk-badge suspicious";
        explanationsContainer.innerHTML = '<div class="loading-spinner">Running real-time analysis...</div>';
    }

    function renderSystemPage() {
        domainDisplay.textContent = "Browser System Page";
        riskScore.textContent = "0%";
        gaugeOuter.style.setProperty("--percentage", "0%");
        gaugeOuter.className = "gauge-outer gauge-safe";
        riskBadge.textContent = "secure";
        riskBadge.className = "risk-badge safe";
        
        explanationsContainer.innerHTML = `
            <div class="exp-item exp-safe">
                <span class="exp-bullet">🛡️</span>
                <span>System utility page protected by the browser shell.</span>
            </div>
        `;
        
        btnWhitelist.style.display = "none";
    }

    // Trust/Whitelist domain handler
    btnWhitelist.addEventListener("click", () => {
        if (!currentTabUrl) return;
        
        const hostname = new URL(currentTabUrl).hostname;
        
        // Sync to backend first (optional fallback if offline)
        fetch("http://localhost:8000/api/whitelist", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain: hostname })
        }).catch(err => console.log("Backend offline, whitelisting locally in extension cache."));
        
        chrome.runtime.sendMessage({
            action: "bypass_warning",
            url: currentTabUrl
        }, (response) => {
            if (response && response.status === "bypassed") {
                // Refresh popup views
                chrome.runtime.sendMessage({
                    action: "get_cached_scan",
                    url: currentTabUrl
                }, (resp) => {
                    if (resp && resp.result) renderScanResult(resp.result);
                });
            }
        });
    });

    // Report Threat handler
    const btnReport = document.getElementById("btn-report");
    if (btnReport) {
        btnReport.addEventListener("click", () => {
            if (!currentTabUrl) return;
            const desc = prompt("Why are you reporting this site? (e.g. 'Fake PayPal login form', 'Mimics Amazon reward check'):");
            if (desc === null) return; // cancelled
            if (!desc.trim()) {
                alert("Please enter a description to report the threat.");
                return;
            }
            
            // Post community report to backend
            fetch("http://localhost:8000/api/reports", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: currentTabUrl, description: desc.trim() })
            })
            .then(res => {
                if (res.ok) {
                    alert("Thank you! Your report has been submitted to PhishGuard community feed.");
                } else {
                    alert("Failed to submit report to backend.");
                }
            })
            .catch(err => {
                console.error("Report submit error:", err);
                alert("Backend offline. Could not submit report.");
            });
        });
    }

    // Launch Dashboard URL in new tab
    const launchDashboard = () => {
        chrome.tabs.create({ url: "http://localhost:8000/dashboard" });
    };

    // Listen for real-time scan updates from background
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === "scan_complete" && request.url === currentTabUrl) {
            renderScanResult(request.result);
        }
        return true;
    });

    btnDashboard.addEventListener("click", launchDashboard);
    openDashboard.addEventListener("click", launchDashboard);
});
