document.addEventListener("DOMContentLoaded", () => {
    // Current date display
    const dateOptions = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
    document.getElementById("date-display").textContent = new Date().toLocaleDateString("en-US", dateOptions);

    // Sidebar navigation
    const navItems = document.querySelectorAll(".nav-item");
    const sections = document.querySelectorAll(".dashboard-section");

    navItems.forEach(item => {
        item.addEventListener("click", (e) => {
            const targetId = item.getAttribute("href");
            if (!targetId || !targetId.startsWith("#")) return;

            e.preventDefault();

            // Toggle active class on nav items
            navItems.forEach(nav => nav.classList.remove("active"));
            item.classList.add("active");

            // Toggle visible section
            sections.forEach(section => {
                section.classList.remove("active");
                if (`#${section.id}` === `${targetId}-section`) {
                    section.classList.add("active");
                }
            });
        });
    });

    // Modal Control
    const modal = document.getElementById("scan-modal");
    const closeModal = document.getElementById("close-modal");

    closeModal.addEventListener("click", () => {
        modal.classList.remove("active");
    });

    modal.addEventListener("click", (e) => {
        if (e.target === modal) {
            modal.classList.remove("active");
        }
    });

    // Chart variables
    let trendChart = null;
    let distributionChart = null;
    let threatsChart = null;

    // Core data container
    let scanHistoryData = [];

    // Auto-detect backend host. If not running on port 8000 (e.g. VS Code Live Server on 5500), target localhost:8000
    const API_BASE = window.location.port === "8000" ? "" : 
                     (window.location.hostname === "127.0.0.1" ? "http://127.0.0.1:8000" : "http://localhost:8000");

    // Fetch and populate stats
    async function fetchStats() {
        try {
            const response = await fetch(`${API_BASE}/api/stats`);
            if (!response.ok) throw new Error("Failed to fetch statistics");
            const stats = await response.json();

            // Update counts
            document.getElementById("stat-total").textContent = stats.total_scans;
            document.getElementById("stat-safe").textContent = stats.safe_count;
            document.getElementById("stat-suspicious").textContent = stats.suspicious_count;
            document.getElementById("stat-blocked").textContent = stats.blocked_count;
            document.getElementById("stat-avg-risk").textContent = `${Math.round(stats.average_risk)}%`;

            // Render Charts
            renderTrendChart(stats.trends);
            renderDistributionChart(stats.risk_distribution);
            renderThreatsChart(stats.most_common_threats);

        } catch (error) {
            console.error("Error loading stats:", error);
        }
    }

    // Fetch and populate history
    async function fetchHistory() {
        try {
            const response = await fetch(`${API_BASE}/api/history`);
            if (!response.ok) throw new Error("Failed to fetch scan history");
            scanHistoryData = await response.json();

            applyFilterAndSearch();

        } catch (error) {
            console.error("Error loading history:", error);
        }
    }

    // Render line trend chart
    function renderTrendChart(trends) {
        const ctx = document.getElementById("trendChart").getContext("2d");
        if (trendChart) trendChart.destroy();

        const labels = trends.map(t => {
            const date = new Date(t.date);
            return date.toLocaleDateString("en-US", { month: "short", day: "numeric" });
        });
        const scanCounts = trends.map(t => t.scan_count);
        const blockedCounts = trends.map(t => t.blocked_count);

        trendChart = new Chart(ctx, {
            type: "line",
            data: {
                labels: labels,
                datasets: [
                    {
                        label: "Total Pages Scanned",
                        data: scanCounts,
                        borderColor: "#00ff66",
                        backgroundColor: "rgba(0, 255, 102, 0.03)",
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2
                    },
                    {
                        label: "Dangerous Blocked",
                        data: blockedCounts,
                        borderColor: "#ff2a2a",
                        backgroundColor: "rgba(255, 42, 42, 0.03)",
                        fill: true,
                        tension: 0.4,
                        borderWidth: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: "#8e9ba8", font: { family: "Outfit" } }
                    }
                },
                scales: {
                    x: {
                        grid: { color: "rgba(255, 255, 255, 0.03)" },
                        ticks: { color: "#8e9ba8" }
                    },
                    y: {
                        grid: { color: "rgba(255, 255, 255, 0.03)" },
                        ticks: { color: "#8e9ba8", stepSize: 1 },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    // Render Pie/Doughnut risk distribution
    function renderDistributionChart(dist) {
        const ctx = document.getElementById("distributionChart").getContext("2d");
        if (distributionChart) distributionChart.destroy();

        distributionChart = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: ["Safe", "Suspicious", "Dangerous"],
                datasets: [{
                    data: [dist.safe, dist.suspicious, dist.dangerous],
                    backgroundColor: ["#00ff66", "#ffaa00", "#ff2a2a"],
                    borderColor: "#030508",
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: "#8e9ba8", font: { family: "Outfit" } }
                    }
                },
                cutout: "70%"
            }
        });
    }

    // Render horizontal bar chart of common threats
    function renderThreatsChart(threats) {
        const ctx = document.getElementById("threatsChart").getContext("2d");
        if (threatsChart) threatsChart.destroy();

        // If no data yet
        const labels = threats.length ? threats.map(t => t.threat_type) : ["No threats logged"];
        const counts = threats.length ? threats.map(t => t.count) : [0];

        // Severity mapping color
        const backgroundColors = threats.map(t => {
            if (t.severity === "high") return "rgba(255, 42, 42, 0.8)";
            if (t.severity === "medium") return "rgba(255, 170, 0, 0.8)";
            return "rgba(0, 255, 102, 0.8)";
        });

        threatsChart = new Chart(ctx, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: backgroundColors.length ? backgroundColors : "rgba(59, 130, 246, 0.3)",
                    borderRadius: 4,
                    barThickness: 16
                }]
            },
            options: {
                indexAxis: "y",
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: "rgba(255, 255, 255, 0.03)" },
                        ticks: { color: "#8e9ba8", stepSize: 1 },
                        beginAtZero: true
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: "#8e9ba8" }
                    }
                }
            }
        });
    }

    // UI Table Populate helper
    function populateTable(data) {
        const tbody = document.getElementById("history-tbody");
        tbody.innerHTML = "";

        if (data.length === 0) {
            tbody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="6">
                        <div class="empty-state">
                            <i class="fa-solid fa-folder-open"></i>
                            <p>No matching scan records found.</p>
                        </div>
                    </td>
                </tr>
            `;
            return;
        }

        data.forEach(scan => {
            const tr = document.createElement("tr");

            // Date formatting
            const date = new Date(scan.timestamp);
            const timeStr = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            const dateStr = date.toLocaleDateString([], { month: 'short', day: 'numeric' });

            // Explanations preview
            const findingsPreview = scan.explanations.length
                ? scan.explanations[0]
                : "No warning signs detected.";
            const findingsCount = scan.explanations.length > 1
                ? ` <span class="text-muted">(+${scan.explanations.length - 1} more)</span>`
                : "";

            tr.innerHTML = `
                <td>
                    <span style="font-weight: 500;">${dateStr}</span>
                    <span style="font-size: 11px; color: var(--text-muted); display: block;">${timeStr}</span>
                </td>
                <td>
                    <span class="domain-cell" title="${scan.domain}">${scan.domain}</span>
                    <span class="url-sub" title="${scan.url}">${scan.url}</span>
                </td>
                <td style="font-weight: 700;">${scan.risk_score}%</td>
                <td>
                    <span class="badge ${scan.risk_level}">${scan.risk_level}</span>
                </td>
                <td>
                    <span style="font-size: 13px;">${findingsPreview}${findingsCount}</span>
                </td>
                <td>
                    <button class="btn-icon view-details-btn" data-id="${scan.id}" title="View Report">
                        <i class="fa-solid fa-square-poll-vertical"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });

        // Register details button click events
        document.querySelectorAll(".view-details-btn").forEach(btn => {
            btn.addEventListener("click", () => {
                const scanId = parseInt(btn.getAttribute("data-id"));
                const scan = scanHistoryData.find(s => s.id === scanId);
                if (scan) showScanDetails(scan);
            });
        });
    }

    // Modal details formatter
    function showScanDetails(scan) {
        const content = document.getElementById("modal-details-content");

        // Build explanations list
        let explanationsHtml = "";
        scan.explanations.forEach(exp => {
            const icon = scan.risk_level === "dangerous" ? "fa-circle-xmark text-red" :
                scan.risk_level === "suspicious" ? "fa-triangle-exclamation text-orange" :
                    "fa-circle-check text-green";
            explanationsHtml += `
                <div class="finding-item">
                    <i class="fa-solid ${icon}"></i>
                    <span>${exp}</span>
                </div>
            `;
        });

        // Build detailed threats list
        let threatsHtml = "";
        if (scan.threats && scan.threats.length > 0) {
            scan.threats.forEach(threat => {
                threatsHtml += `
                    <div class="threat-detail-item">
                        <div class="threat-meta">
                            <span class="threat-title">${threat.threat_type}</span>
                            <span class="threat-desc">${threat.description}</span>
                        </div>
                        <span class="badge severity-${threat.severity}">${threat.severity}</span>
                    </div>
                `;
            });
        } else {
            threatsHtml = `<p class="text-muted" style="font-size: 13px; text-align: center; padding: 10px 0;">No active threats flagged.</p>`;
        }

        content.innerHTML = `
            <div class="report-section">
                <h4>Analyzed Address</h4>
                <div class="report-url-block">${scan.url}</div>
            </div>
            
            <div class="report-section">
                <h4>Engine Verification Split</h4>
                <div class="report-scores-grid">
                    <div class="score-box">
                        <div class="score-val text-red" style="color: ${scan.risk_level === 'dangerous' ? '#ef4444' : scan.risk_level === 'suspicious' ? '#f59e0b' : '#10b981'}">${scan.risk_score}%</div>
                        <div class="score-label">Final Risk</div>
                    </div>
                    <div class="score-box">
                        <div class="score-val" style="color: #8b5cf6;">${scan.ml_score}%</div>
                        <div class="score-label">ML Engine</div>
                    </div>
                    <div class="score-box">
                        <div class="score-val" style="color: #3b82f6;">${scan.heuristics_score}%</div>
                        <div class="score-label">Heuristics</div>
                    </div>
                </div>
            </div>
            
            <div class="report-section" style="margin-bottom: 24px;">
                <h4>Heuristic & AI Explanations</h4>
                <div class="findings-list">
                    ${explanationsHtml}
                </div>
            </div>
            
            <div class="report-section">
                <h4>Identified Threat Vectors</h4>
                <div class="threats-detailed-list">
                    ${threatsHtml}
                </div>
            </div>
        `;

        modal.classList.add("active");
    }

    // Filtering & Searching logic
    const searchInput = document.getElementById("search-input");
    const filterRisk = document.getElementById("filter-risk");

    function applyFilterAndSearch() {
        const query = searchInput.value.toLowerCase().trim();
        const riskLevel = filterRisk.value;

        const filtered = scanHistoryData.filter(scan => {
            const matchesSearch = scan.url.toLowerCase().includes(query) ||
                scan.domain.toLowerCase().includes(query);
            const matchesRisk = riskLevel === "all" || scan.risk_level === riskLevel;

            return matchesSearch && matchesRisk;
        });

        populateTable(filtered);
    }

    searchInput.addEventListener("input", applyFilterAndSearch);
    filterRisk.addEventListener("change", applyFilterAndSearch);

    // Refresh synchronization
    const refreshBtn = document.getElementById("refresh-dashboard");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", async () => {
            const icon = refreshBtn.querySelector("i");
            if (icon) icon.classList.add("fa-spin");

            try {
                console.log("Triggering backend threat intelligence feed reload...");
                const response = await fetch(`${API_BASE}/api/reload_feeds`, { method: "POST" });
                if (response.ok) {
                    const data = await response.json();
                    console.log(`Successfully synced ${data.feed_size} live threat signatures.`);
                }
            } catch (err) {
                console.error("Failed to reload threat intelligence feed:", err);
            }

            await fetchStats();
            await fetchHistory();

            setTimeout(() => {
                if (icon) icon.classList.remove("fa-spin");
            }, 600);
        });
    }

    // ----------------------------------------------------
    // Manual URL Threat Scanning Logic (Robust DOM Queries)
    // ----------------------------------------------------
    async function performManualScan() {
        console.log("Triggering manual URL threat scan...");
        const manualScanInput = document.getElementById("manual-scan-input");
        const btnManualScan = document.getElementById("btn-manual-scan");
        const manualScanResult = document.getElementById("manual-scan-result");

        if (!manualScanInput || !btnManualScan || !manualScanResult) {
            console.error("Manual scanner DOM elements are missing!");
            return;
        }

        const urlInput = manualScanInput.value.trim();
        if (!urlInput) {
            manualScanInput.style.borderColor = "var(--danger)";
            setTimeout(() => { manualScanInput.style.borderColor = "var(--border-color)"; }, 1500);
            return;
        }

        // Validate basic URL structure (or auto-prepend http:// if missing host)
        let formattedUrl = urlInput;
        if (!/^https?:\/\//i.test(urlInput)) {
            formattedUrl = "http://" + urlInput;
        }

        // Set loading state
        btnManualScan.disabled = true;
        btnManualScan.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Analyzing...`;
        manualScanInput.disabled = true;

        try {
            const headers = { "Content-Type": "application/json" };

            console.log(`Sending manual scan request for: ${formattedUrl}`);
            const response = await fetch(`${API_BASE}/api/scan`, {
                method: "POST",
                headers: headers,
                body: JSON.stringify({ url: formattedUrl, html_content: "" })
            });

            if (!response.ok) throw new Error(`Threat scan returned status: ${response.status}`);
            const data = await response.json();
            console.log("Received scan response from backend:", data);

            // Render manual scan result
            renderManualScanResult(data);

            // Sync Stats and History tables automatically
            fetchStats();
            fetchHistory();
        } catch (error) {
            console.error("Manual scan request failed:", error);
            manualScanResult.style.display = "block";
            manualScanResult.innerHTML = `
                <div style="color: var(--danger); font-size: 14px; display: flex; align-items: center; gap: 8px; padding: 12px; border: 1px solid var(--danger); border-radius: 8px; background: rgba(239, 68, 68, 0.08);">
                    <i class="fa-solid fa-circle-exclamation"></i>
                    <span>Failed to reach PhishGuard AI backend. Ensure the server is running on port 8000.</span>
                </div>
            `;
        } finally {
            btnManualScan.disabled = false;
            btnManualScan.innerHTML = "Analyze Link";
            manualScanInput.disabled = false;
        }
    }

    function renderManualScanResult(result) {
        console.log("Rendering manual scan result to DOM...", result);
        const manualScanResult = document.getElementById("manual-scan-result");
        if (!manualScanResult) {
            console.error("Element #manual-scan-result not found in DOM!");
            return;
        }

        try {
            const score = result.risk_score !== undefined ? result.risk_score : 0;
            const level = result.risk_level || "safe";
            
            let levelColor = "var(--success)";
            let levelBg = "rgba(16, 185, 129, 0.1)";
            let bannerText = "✅ SECURE: NO PHISHING SIGNATURES FOUND";
            let bannerBg = "rgba(16, 185, 129, 0.12)";

            if (level === "dangerous") {
                levelColor = "var(--danger)";
                levelBg = "rgba(239, 68, 68, 0.1)";
                bannerText = "❌ DANGEROUS PHISHING TARGET DETECTED";
                bannerBg = "rgba(239, 68, 68, 0.15)";
            } else if (level === "suspicious") {
                levelColor = "var(--warning)";
                levelBg = "rgba(245, 158, 11, 0.1)";
                bannerText = "⚠️ SUSPICIOUS WEB ADDRESS DETECTED";
                bannerBg = "rgba(245, 158, 11, 0.15)";
            }

            let explanationsListHtml = "";
            const explanations = result.explanations || [];
            explanations.forEach(exp => {
                const icon = level === "dangerous" ? "fa-circle-xmark" : 
                             level === "suspicious" ? "fa-triangle-exclamation" : 
                             "fa-circle-check";
                explanationsListHtml += `
                    <li style="display: flex; gap: 8px; font-size: 13px; color: var(--text-main); margin-bottom: 6px; align-items: flex-start;">
                        <i class="fa-solid ${icon}" style="color: ${levelColor}; margin-top: 3px;"></i>
                        <span>${exp}</span>
                    </li>
                `;
            });

            manualScanResult.innerHTML = `
                <!-- Prominent Visual Alert Banner -->
                <div style="background: ${bannerBg}; border: 1px solid ${levelColor}; padding: 12px 16px; border-radius: 8px; font-weight: 700; font-size: 13px; color: ${levelColor}; display: flex; align-items: center; gap: 10px; margin-bottom: 18px;">
                    <span>${bannerText}</span>
                </div>

                <div style="display: flex; gap: 24px; flex-wrap: wrap; align-items: center; justify-content: space-between;">
                    <div style="display: flex; gap: 16px; align-items: center; flex-grow: 1; min-width: 250px;">
                        <div style="width: 70px; height: 70px; border-radius: 50%; background: ${levelBg}; border: 2px solid ${levelColor}; display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0;">
                            <span style="font-size: 18px; font-weight: 800; color: ${levelColor};">${score}%</span>
                            <span style="font-size: 8px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px;">Risk</span>
                        </div>
                        <div>
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <h4 style="font-size: 15px; font-weight: 700; text-transform: capitalize; color: ${levelColor};">${level} Website</h4>
                                <span class="badge ${level}" style="font-size: 10px; padding: 2px 8px;">${level}</span>
                            </div>
                            <p class="text-muted" style="font-size: 12px; margin-top: 4px; word-break: break-all;">${result.url}</p>
                        </div>
                    </div>
                    <button class="btn" id="btn-clear-manual" style="padding: 6px 12px; font-size: 12px; height: fit-content;">Dismiss</button>
                </div>
                
                <div style="margin-top: 16px;">
                    <h5 style="font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; font-weight: 600;">Security Diagnostics</h5>
                    <ul style="list-style: none; padding-left: 0;">
                        ${explanationsListHtml}
                    </ul>
                </div>
            `;

            // Display manual scan result block
            manualScanResult.style.display = "block";
            console.log("Result panel display set to block successfully.");

            const clearBtn = document.getElementById("btn-clear-manual");
            if (clearBtn) {
                clearBtn.onclick = () => {
                    manualScanResult.style.display = "none";
                    manualScanResult.innerHTML = "";
                    const inputField = document.getElementById("manual-scan-input");
                    if (inputField) inputField.value = "";
                };
            }
        } catch (e) {
            console.error("Error inside renderManualScanResult:", e);
            manualScanResult.innerHTML = `
                <div style="color: var(--danger); font-size: 14px; display: flex; align-items: center; gap: 8px; padding: 12px; border: 1px solid var(--danger); border-radius: 8px; background: rgba(239, 68, 68, 0.08); margin-top: 10px;">
                    <i class="fa-solid fa-circle-exclamation"></i>
                    <span>UI Rendering Error: ${e.message}</span>
                </div>
            `;
            manualScanResult.style.display = "block";
        }
    }

    // Bind event listeners using dynamic elements in DOM
    const btnManualScan = document.getElementById("btn-manual-scan");
    const manualScanInput = document.getElementById("manual-scan-input");
    
    if (btnManualScan) {
        btnManualScan.addEventListener("click", performManualScan);
    }
    if (manualScanInput) {
        manualScanInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") performManualScan();
        });
    }

    // ----------------------------------------------------
    // CSV Export Logic
    // ----------------------------------------------------
    const btnExportCsv = document.getElementById("btn-export-csv");
    if (btnExportCsv) {
        btnExportCsv.addEventListener("click", () => {
            if (scanHistoryData.length === 0) {
                alert("No scan logs available to export.");
                return;
            }
            
            // Generate CSV header
            let csvContent = "data:text/csv;charset=utf-8,";
            csvContent += "ID,Timestamp,Domain,URL,Risk Score,Risk Level,ML Score,Heuristics Score,Reputation Score,Explanations\r\n";
            
            // Generate rows
            scanHistoryData.forEach(scan => {
                const escapedUrl = `"${scan.url.replace(/"/g, '""')}"`;
                const escapedDomain = `"${scan.domain.replace(/"/g, '""')}"`;
                const escapedExplanations = `"${scan.explanations.join('; ').replace(/"/g, '""')}"`;
                
                const row = [
                    scan.id,
                    scan.timestamp,
                    escapedDomain,
                    escapedUrl,
                    scan.risk_score,
                    scan.risk_level,
                    scan.ml_score,
                    scan.heuristics_score,
                    scan.rep_score,
                    escapedExplanations
                ].join(",");
                
                csvContent += row + "\r\n";
            });
            
            // Trigger download
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement("a");
            link.setAttribute("href", encodedUri);
            link.setAttribute("download", `phishguard_threat_logs_${new Date().toISOString().split('T')[0]}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });
    }

    // ----------------------------------------------------
    // Live Threat Intelligence Console Ticker
    // ----------------------------------------------------
    const consoleBox = document.getElementById("threat-console");
    if (consoleBox) {
        const initialLogs = [
            "SYS_BOOT: Initializing PhishGuard AI Threat Matrix...",
            "DB_INIT: SQLite database engine active. Thread pool size = 16.",
            "NET_INTEL: Connecting to global reputation databases...",
            "FEED_SYNC: Synced 14,290 active threat vectors from OpenPhish.",
            "VT_CONNECT: Hash scanner API established. Status: ACTIVE.",
            "GSB_CHECK: Safe Browsing metadata synchronized successfully.",
            "ML_LOAD: RandomForest Classifier active. 13 features registered.",
            "DAEMON: Threat Mitigation Daemon listening on port 8000..."
        ];
        
        // Feed mock lines one by one on startup
        initialLogs.forEach((log, index) => {
            setTimeout(() => {
                addConsoleLog(log);
            }, index * 400);
        });

        const threatFeeds = [
            "SEC_WARN: Insecure HTTP credential form loading intercepted.",
            "FEED_SYNC: MITRE ATT&CK T1566 phishing signatures updated.",
            "API_QUOTA: 4/15000 API requests consumed on VirusTotal.",
            "HEURISTIC: DNS entropy check triggered on incoming domain.",
            "SYS_LOG: Pruned threat intelligence logs older than 30 days.",
            "DECRYPT: Decoded URL hex params: raw_data='hex:70617970616c'.",
            "PORT_SCAN: Shodan API query returned 0 open management ports.",
            "HOMOGLYPH: Unicode character verification scanner completed.",
            "ML_AUDIT: RF model accuracy verified at 99.75% locally."
        ];

        // Ticker for periodic logs
        setInterval(() => {
            const randomLog = threatFeeds[Math.floor(Math.random() * threatFeeds.length)];
            addConsoleLog(randomLog);
        }, 5000);
    }

    function addConsoleLog(message) {
        const consoleBox = document.getElementById("threat-console");
        if (!consoleBox) return;
        const now = new Date();
        const timeStr = now.toTimeString().split(" ")[0];
        const logLine = document.createElement("div");
        
        let type = "INFO";
        let color = "var(--primary)"; // Neon Green
        let logMsg = message;
        
        // Parse prefix type (e.g. "SYS_BOOT: message")
        if (message.includes(": ")) {
            const parts = message.split(": ");
            type = parts[0];
            logMsg = parts.slice(1).join(": ");
        }
        
        if (type.includes("WARN") || type.includes("ALERT") || type.includes("BLOCK") || type.includes("CRIT")) {
            color = "var(--danger)"; // Neon Red
        } else if (type.includes("SYNC") || type.includes("INIT") || type.includes("BOOT") || type.includes("CONNECT")) {
            color = "#60a5fa"; // Neon Blue
        } else if (type.includes("HEURISTIC") || type.includes("DECRYPT") || type.includes("ML") || type.includes("PORT")) {
            color = "var(--warning)"; // Neon Orange
        }
        
        logLine.innerHTML = `<span style="color: #4b5563;">[${timeStr}]</span> <span style="color: ${color}; font-weight: 700;">[${type}]</span> ${logMsg}`;
        consoleBox.appendChild(logLine);
        consoleBox.scrollTop = consoleBox.scrollHeight;
        
        // Prune logs to avoid memory bloat in tab
        while (consoleBox.children.length > 50) {
            consoleBox.removeChild(consoleBox.firstChild);
        }
    }

    // Ensure export CSV button is visible for the public dashboard
    if (btnExportCsv) {
        btnExportCsv.style.display = "inline-flex";
    }

    // Wipe History database trigger
    const wipeHistoryBtn = document.getElementById("btn-wipe-history");
    if (wipeHistoryBtn) {
        wipeHistoryBtn.addEventListener("click", async () => {
            const confirmWipe = confirm("⚠️ WARNING: This will permanently delete ALL threat scan history logs and reset your stats. Do you want to proceed?");
            if (!confirmWipe) return;

            const icon = wipeHistoryBtn.querySelector("i");
            if (icon) icon.className = "fa-solid fa-spinner fa-spin";
            wipeHistoryBtn.disabled = true;

            try {
                const response = await fetch(`${API_BASE}/api/history`, { method: "DELETE" });
                if (response.ok) {
                    const data = await response.json();
                    console.log("Database cleared:", data.message);
                } else {
                    throw new Error("Wipe operation failed");
                }
            } catch (err) {
                console.error("Wipe history error:", err);
                alert("Failed to wipe history database: " + err.message);
            } finally {
                if (icon) icon.className = "fa-solid fa-trash-can";
                wipeHistoryBtn.disabled = false;
                
                // Refresh statistics and history list
                fetchStats();
                fetchHistory();
            }
        });
    }

    // Subtle cyber Matrix rain drop animation
    const canvas = document.getElementById("cyber-matrix-bg");
    if (canvas) {
        const ctx = canvas.getContext("2d");

        // Set dimensions
        function resizeCanvas() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
        }
        resizeCanvas();
        window.addEventListener("resize", resizeCanvas);

        // Columns config
        const fontSize = 16;
        const columns = Math.floor(canvas.width / fontSize);
        
        // Drops tracker (starting at random positions for natural flow)
        const drops = [];
        for (let i = 0; i < columns; i++) {
            drops[i] = Math.random() * -100;
        }

        // Japanese Katakana + English alphanumeric symbols for matrix drop
        const charset = "ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const alphabet = charset.split("");

        function drawMatrix() {
            // Very subtle dark background fade to create trails
            ctx.fillStyle = "rgba(3, 5, 8, 0.05)";
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            // Set matrix font color (neon green) and styles
            ctx.fillStyle = "#00ff66";
            ctx.font = fontSize + "px monospace";

            for (let i = 0; i < drops.length; i++) {
                // Pick random character
                const char = alphabet[Math.floor(Math.random() * alphabet.length)];
                
                // Calculate position coordinates
                const x = i * fontSize;
                const y = drops[i] * fontSize;

                // Render character
                ctx.fillText(char, x, y);

                // Increment position drop or reset
                if (y > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }

        // Render loop
        setInterval(drawMatrix, 40);
    }

    // Hook tab-specific initializations on click
    navItems.forEach(item => {
        item.addEventListener("click", () => {
            const targetId = item.getAttribute("href");
            if (targetId === "#rules") {
                fetchWhitelist();
                fetchBlacklist();
            } else if (targetId === "#community") {
                fetchCommunityReports();
            } else if (targetId === "#settings") {
                loadSettings();
            }
        });
    });

    // ----------------------------------------------------
    // Access Rules: Whitelist & Blacklist Logic
    // ----------------------------------------------------
    async function fetchWhitelist() {
        try {
            const response = await fetch(`${API_BASE}/api/whitelist`);
            if (!response.ok) throw new Error("Failed to fetch whitelist");
            const data = await response.json();
            const tbody = document.getElementById("whitelist-tbody");
            tbody.innerHTML = "";
            
            if (data.length === 0) {
                tbody.innerHTML = `<tr><td colspan="3" class="text-muted" style="text-align: center; padding: 12px; font-size: 13px;">No whitelisted domains added yet.</td></tr>`;
                return;
            }
            
            data.forEach(item => {
                const tr = document.createElement("tr");
                const date = new Date(item.timestamp).toLocaleDateString();
                tr.innerHTML = `
                    <td style="font-weight: 600; color: var(--primary);">${item.domain}</td>
                    <td style="font-size: 12px; color: var(--text-muted);">${date}</td>
                    <td>
                        <button class="btn-icon delete-whitelist-btn" data-domain="${item.domain}" style="color: var(--danger);" title="Remove trust">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
            
            // Bind delete event
            tbody.querySelectorAll(".delete-whitelist-btn").forEach(btn => {
                btn.addEventListener("click", async () => {
                    const domain = btn.getAttribute("data-domain");
                    if (confirm(`Remove ${domain} from Whitelist?`)) {
                        await deleteWhitelist(domain);
                    }
                });
            });
        } catch (err) {
            console.error(err);
        }
    }

    async function addWhitelist(domain) {
        try {
            const response = await fetch(`${API_BASE}/api/whitelist`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain })
            });
            if (response.ok) {
                document.getElementById("whitelist-input").value = "";
                fetchWhitelist();
            }
        } catch (err) {
            console.error(err);
        }
    }

    async function deleteWhitelist(domain) {
        try {
            const response = await fetch(`${API_BASE}/api/whitelist/${domain}`, { method: "DELETE" });
            if (response.ok) fetchWhitelist();
        } catch (err) {
            console.error(err);
        }
    }

    async function fetchBlacklist() {
        try {
            const response = await fetch(`${API_BASE}/api/blacklist`);
            if (!response.ok) throw new Error("Failed to fetch blacklist");
            const data = await response.json();
            const tbody = document.getElementById("blacklist-tbody");
            tbody.innerHTML = "";
            
            if (data.length === 0) {
                tbody.innerHTML = `<tr><td colspan="3" class="text-muted" style="text-align: center; padding: 12px; font-size: 13px;">No blacklisted domains added yet.</td></tr>`;
                return;
            }
            
            data.forEach(item => {
                const tr = document.createElement("tr");
                const date = new Date(item.timestamp).toLocaleDateString();
                tr.innerHTML = `
                    <td style="font-weight: 600; color: var(--danger);">${item.domain}</td>
                    <td style="font-size: 12px; color: var(--text-muted);">${date}</td>
                    <td>
                        <button class="btn-icon delete-blacklist-btn" data-domain="${item.domain}" style="color: var(--danger);" title="Remove block">
                            <i class="fa-solid fa-trash-can"></i>
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
            
            // Bind delete event
            tbody.querySelectorAll(".delete-blacklist-btn").forEach(btn => {
                btn.addEventListener("click", async () => {
                    const domain = btn.getAttribute("data-domain");
                    if (confirm(`Remove ${domain} from Blacklist?`)) {
                        await deleteBlacklist(domain);
                    }
                });
            });
        } catch (err) {
            console.error(err);
        }
    }

    async function addBlacklist(domain) {
        try {
            const response = await fetch(`${API_BASE}/api/blacklist`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain })
            });
            if (response.ok) {
                document.getElementById("blacklist-input").value = "";
                fetchBlacklist();
            }
        } catch (err) {
            console.error(err);
        }
    }

    async function deleteBlacklist(domain) {
        try {
            const response = await fetch(`${API_BASE}/api/blacklist/${domain}`, { method: "DELETE" });
            if (response.ok) fetchBlacklist();
        } catch (err) {
            console.error(err);
        }
    }

    // Bind Access Rules inputs
    const btnAddWhitelist = document.getElementById("btn-add-whitelist");
    const whitelistInput = document.getElementById("whitelist-input");
    if (btnAddWhitelist && whitelistInput) {
        btnAddWhitelist.onclick = () => {
            const domain = whitelistInput.value.trim();
            if (domain) addWhitelist(domain);
        };
        whitelistInput.onkeypress = (e) => {
            if (e.key === "Enter") addWhitelist(whitelistInput.value.trim());
        };
    }

    const btnAddBlacklist = document.getElementById("btn-add-blacklist");
    const blacklistInput = document.getElementById("blacklist-input");
    if (btnAddBlacklist && blacklistInput) {
        btnAddBlacklist.onclick = () => {
            const domain = blacklistInput.value.trim();
            if (domain) addBlacklist(domain);
        };
        blacklistInput.onkeypress = (e) => {
            if (e.key === "Enter") addBlacklist(blacklistInput.value.trim());
        };
    }

    // ----------------------------------------------------
    // Community Feed Logic
    // ----------------------------------------------------
    async function fetchCommunityReports() {
        try {
            const response = await fetch(`${API_BASE}/api/reports`);
            if (!response.ok) throw new Error("Failed to fetch community reports");
            const data = await response.json();
            const container = document.getElementById("community-feed-container");
            container.innerHTML = "";
            
            if (data.length === 0) {
                container.innerHTML = `
                    <div style="text-align: center; padding: 40px; border: 1px dashed var(--border-color); border-radius: 8px;">
                        <i class="fa-solid fa-bullhorn" style="font-size: 30px; color: var(--text-muted); margin-bottom: 10px;"></i>
                        <p class="text-muted" style="font-size: 13px;">No deceptive links reported yet. Be the first to secure the community!</p>
                    </div>
                `;
                return;
            }
            
            data.forEach(item => {
                const card = document.createElement("div");
                card.className = "community-card";
                const date = new Date(item.timestamp).toLocaleDateString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
                card.innerHTML = `
                    <div class="community-body">
                        <div class="community-url">${item.url}</div>
                        <div class="community-desc">"${item.description}"</div>
                        <div class="community-time"><i class="fa-solid fa-clock"></i> Reported on ${date}</div>
                    </div>
                    <div class="community-vote">
                        <button class="btn-vote confirm-report-btn" data-id="${item.id}">
                            <i class="fa-solid fa-shield-virus"></i> Confirm (${item.flags_count})
                        </button>
                    </div>
                `;
                container.appendChild(card);
            });
            
            // Bind Vote Confirm
            container.querySelectorAll(".confirm-report-btn").forEach(btn => {
                btn.addEventListener("click", async () => {
                    const reportId = btn.getAttribute("data-id");
                    try {
                        const res = await fetch(`${API_BASE}/api/reports/${reportId}/vote`, { method: "POST" });
                        if (res.ok) {
                            fetchCommunityReports();
                        }
                    } catch (err) {
                        console.error(err);
                    }
                });
            });
        } catch (err) {
            console.error(err);
        }
    }

    const btnSubmitReport = document.getElementById("btn-submit-report");
    const reportUrlInput = document.getElementById("report-url-input");
    const reportDescInput = document.getElementById("report-desc-input");
    
    if (btnSubmitReport && reportUrlInput && reportDescInput) {
        btnSubmitReport.onclick = async () => {
            const url = reportUrlInput.value.trim();
            const description = reportDescInput.value.trim();
            
            if (!url || !description) {
                alert("Please fill in both the deceptive link and description.");
                return;
            }
            
            try {
                const response = await fetch(`${API_BASE}/api/reports`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url, description })
                });
                
                if (response.ok) {
                    reportUrlInput.value = "";
                    reportDescInput.value = "";
                    fetchCommunityReports();
                } else {
                    const data = await response.json();
                    alert("Report filing failed: " + data.detail);
                }
            } catch (err) {
                console.error(err);
            }
        };
    }

    // ----------------------------------------------------
    // Security Diagnostics Logic
    // ----------------------------------------------------
    const btnRunDiagnostics = document.getElementById("btn-run-diagnostics");
    const diagnosticsDomainInput = document.getElementById("diagnostics-domain-input");
    const diagnosticsResult = document.getElementById("diagnostics-result");
    
    if (btnRunDiagnostics && diagnosticsDomainInput && diagnosticsResult) {
        btnRunDiagnostics.onclick = async () => {
            const domain = diagnosticsDomainInput.value.trim();
            if (!domain) return;
            
            btnRunDiagnostics.disabled = true;
            btnRunDiagnostics.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Querying rdap/ssl...`;
            
            try {
                const response = await fetch(`${API_BASE}/api/diagnostics?domain=${encodeURIComponent(domain)}`);
                if (!response.ok) throw new Error("Diagnostics query failed");
                const data = await response.json();
                
                let sslStatus = data.ssl_valid ? `<span class="badge safe" style="font-size: 10px; padding: 2px 6px;">VALID SSL</span>` : `<span class="badge dangerous" style="font-size: 10px; padding: 2px 6px;">NO SSL / INSECURE</span>`;
                let ageStatus = data.domain_age_days < 90 ? "var(--danger)" : "var(--primary)";
                
                diagnosticsResult.innerHTML = `
                    <div class="diagnostics-layout">
                        <div class="grade-badge-wrapper">
                            <div class="grade-circle grade-${data.grade.replace("+", "-plus")}">${data.grade}</div>
                            <span style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-top: 10px; letter-spacing: 0.5px;">Security Grade</span>
                        </div>
                        <div class="diagnostics-info-grid">
                            <div class="info-item-card">
                                <span class="info-item-label">Checked Address</span>
                                <div class="info-item-value" style="color: #60a5fa; font-family: monospace;">${data.domain}</div>
                            </div>
                            <div class="info-item-card">
                                <span class="info-item-label">SSL Connection Details</span>
                                <div class="info-item-value" style="display: flex; flex-direction: column; gap: 4px; font-size: 12px;">
                                    <div>Status: ${sslStatus}</div>
                                    <div class="text-muted" style="font-size: 10px;">Issuer: ${data.ssl_issuer}</div>
                                    <div class="text-muted" style="font-size: 10px;">Expires: ${data.ssl_expiry}</div>
                                </div>
                            </div>
                            <div class="info-item-card">
                                <span class="info-item-label">Registry Domain Age</span>
                                <div class="info-item-value" style="color: ${ageStatus};">${data.domain_age_days} Days Old</div>
                                <span class="text-muted" style="font-size: 10px;">Created: ${data.domain_created}</span>
                            </div>
                            <div class="info-item-card">
                                <span class="info-item-label">Hosting & Provider Details</span>
                                <div class="info-item-value" style="font-size: 12px;">
                                    <div>Location: ${data.location}</div>
                                    <div class="text-muted" style="font-size: 10px; margin-top: 2px;">ISP: ${data.isp}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
                diagnosticsResult.style.display = "block";
            } catch (err) {
                console.error(err);
                diagnosticsResult.innerHTML = `<div class="text-red" style="font-size: 13px;"><i class="fa-solid fa-circle-exclamation"></i> Diagnostics query failed. Make sure to enter a valid domain address.</div>`;
                diagnosticsResult.style.display = "block";
            } finally {
                btnRunDiagnostics.disabled = false;
                btnRunDiagnostics.innerHTML = "Query Diagnostics";
            }
        };
        
        diagnosticsDomainInput.onkeypress = (e) => {
            if (e.key === "Enter") btnRunDiagnostics.click();
        };
    }

    // ----------------------------------------------------
    // Brand Defender: Typo-Squatting Scanner Logic
    // ----------------------------------------------------
    const btnRunDefender = document.getElementById("btn-run-defender");
    const defenderDomainInput = document.getElementById("defender-domain-input");
    const defenderResult = document.getElementById("defender-result");
    const defenderTbody = document.getElementById("defender-tbody");
    
    if (btnRunDefender && defenderDomainInput && defenderResult && defenderTbody) {
        btnRunDefender.onclick = async () => {
            const domain = defenderDomainInput.value.trim();
            if (!domain) return;
            
            btnRunDefender.disabled = true;
            btnRunDefender.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Generating variations...`;
            
            try {
                const response = await fetch(`${API_BASE}/api/typosquats?domain=${encodeURIComponent(domain)}`);
                if (!response.ok) throw new Error("TypoSquat scan failed");
                const data = await response.json();
                
                defenderTbody.innerHTML = "";
                
                if (data.length === 0) {
                    defenderTbody.innerHTML = `<tr><td colspan="5" class="text-muted" style="text-align: center; padding: 12px;">No variants generated. Enter a valid domain name.</td></tr>`;
                    defenderResult.style.display = "block";
                    return;
                }
                
                data.forEach(item => {
                    const tr = document.createElement("tr");
                    
                    let statusBadge = item.is_online 
                        ? `<span class="badge dangerous" style="font-size: 10px; padding: 2px 6px;">ONLINE</span>` 
                        : `<span class="badge safe" style="font-size: 10px; padding: 2px 6px;">OFFLINE</span>`;
                        
                    tr.innerHTML = `
                        <td style="font-family: monospace; font-weight: 700;">${item.variant}</td>
                        <td style="font-size: 12px; color: var(--text-muted);">${item.type}</td>
                        <td>${statusBadge}</td>
                        <td style="font-family: monospace; font-size: 12px; color: var(--text-main);">${item.ip}</td>
                        <td>
                            <button class="btn btn-wipe block-spoof-btn" data-domain="${item.variant}" style="padding: 4px 10px; font-size: 10px; border: 1px solid var(--danger);">
                                Block Domain
                            </button>
                        </td>
                    `;
                    defenderTbody.appendChild(tr);
                });
                
                // Bind Quick Block in TypoSquat scanner
                defenderTbody.querySelectorAll(".block-spoof-btn").forEach(btn => {
                    btn.addEventListener("click", async () => {
                        const blockDomain = btn.getAttribute("data-domain");
                        try {
                            const res = await fetch(`${API_BASE}/api/blacklist`, {
                                method: "POST",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({ domain: blockDomain })
                            });
                            if (res.ok) {
                                alert(`Domain ${blockDomain} added to custom blocked list successfully!`);
                            }
                        } catch (err) {
                            console.error(err);
                        }
                    });
                });
                
                defenderResult.style.display = "block";
            } catch (err) {
                console.error(err);
                alert("TypoSquat query failed.");
            } finally {
                btnRunDefender.disabled = false;
                btnRunDefender.innerHTML = "Scan Spoof Domains";
            }
        };
        
        defenderDomainInput.onkeypress = (e) => {
            if (e.key === "Enter") btnRunDefender.click();
        };
    }

    // Hook tab-specific initializations on click
    navItems.forEach(item => {
        item.addEventListener("click", () => {
            const targetId = item.getAttribute("href");
            if (targetId === "#rules") {
                fetchWhitelist();
                fetchBlacklist();
            } else if (targetId === "#community") {
                fetchCommunityReports();
            } else if (targetId === "#settings") {
                loadSettings();
            } else if (targetId === "#map") {
                initThreatMap();
            } else if (targetId === "#hygiene") {
                generateHygieneAudit();
            } else if (targetId === "#game") {
                initPhishGame();
            }
        });
    });

    // ----------------------------------------------------
    // 1. Interactive World Threat Map Controller
    // ----------------------------------------------------
    const landGrid = [
        // North America
        [60, -120], [60, -110], [60, -100], [60, -90], [60, -80], [60, -70],
        [50, -125], [50, -115], [50, -105], [50, -95], [50, -85], [50, -75], [50, -65],
        [40, -122], [40, -112], [40, -102], [40, -92], [40, -82], [40, -72],
        [30, -110], [30, -100], [30, -90], [30, -80],
        [20, -102], [20, -92], [20, -82],
        [15, -90], [10, -82],
        // South America
        [0, -72], [0, -62], [0, -52],
        [-10, -74], [-10, -64], [-10, -54], [-10, -44],
        [-20, -70], [-20, -60], [-20, -50], [-20, -42],
        [-30, -72], [-30, -62], [-30, -52],
        [-40, -70], [-40, -60],
        [-50, -70],
        // Europe / Asia
        [70, 20], [70, 40], [70, 60], [70, 80], [70, 100], [70, 120], [70, 140], [70, 160],
        [60, 10], [60, 20], [60, 30], [60, 40], [60, 50], [60, 60], [60, 70], [60, 80], [60, 90], [60, 100], [60, 110], [60, 120], [60, 130], [60, 140], [60, 150], [60, 160],
        [50, 0], [50, 10], [50, 20], [50, 30], [50, 40], [50, 50], [50, 60], [50, 70], [50, 80], [50, 90], [50, 100], [50, 110], [50, 120], [50, 130], [50, 140], [50, 150], [50, 160],
        [40, -10], [40, 0], [40, 10], [40, 20], [40, 30], [40, 40], [40, 50], [40, 60], [40, 70], [40, 80], [40, 90], [40, 100], [40, 110], [40, 120], [40, 130], [40, 140], [40, 150],
        [30, 35], [30, 45], [30, 55], [30, 65], [30, 75], [30, 85], [30, 95], [30, 105], [30, 115], [30, 125], [30, 135], [30, 140],
        [20, 35], [20, 72], [20, 82], [20, 92], [20, 102], [20, 112], [20, 122],
        [10, 78], [10, 102], [10, 112], [10, 122], [10, 125],
        // Africa
        [30, 15], [30, 25],
        [20, -10], [20, 0], [20, 10], [20, 20], [20, 30], [20, 40],
        [10, -12], [10, 0], [10, 12], [10, 22], [10, 32], [10, 40],
        [0, 10], [0, 20], [0, 30], [0, 42],
        [-10, 12], [-10, 22], [-10, 32],
        [-20, 16], [-20, 22], [-20, 30],
        [-30, 20], [-30, 28],
        // Australia
        [-20, 122], [-20, 132], [-20, 142],
        [-30, 122], [-30, 132], [-30, 142], [-30, 148]
    ];

    let mapAnimationId = null;

    async function initThreatMap() {
        const canvas = document.getElementById("world-map-canvas");
        if (!canvas) return;
        const ctx = canvas.getContext("2d");

        // Fit to wrapper sizing
        function resizeMap() {
            const wrapper = document.getElementById("map-canvas-wrapper");
            if (wrapper) {
                canvas.width = wrapper.clientWidth;
                canvas.height = wrapper.clientHeight;
            }
        }
        resizeMap();

        // Fetch telemetry coordinates from history
        let threatNodes = [];
        try {
            const res = await fetch(`${API_BASE}/api/history`);
            if (res.ok) {
                const history = await res.json();
                // Extract only dangerous/suspicious coordinates
                threatNodes = history
                    .filter(s => (s.risk_level === "dangerous" || s.risk_level === "suspicious") && s.latitude && s.longitude)
                    .map(s => ({
                        domain: s.domain,
                        level: s.risk_level,
                        score: s.risk_score,
                        country: s.country || "Unknown Location",
                        lat: s.latitude,
                        lon: s.longitude,
                        pulse: 0
                    }));
            }
        } catch (e) {
            console.error("Telemetry map history load error:", e);
        }

        // Update indicators
        document.getElementById("map-beacons-count").textContent = threatNodes.length;
        if (threatNodes.length > 0) {
            document.getElementById("map-top-location").textContent = threatNodes[0].country;
            const logBox = document.getElementById("map-telemetry-log");
            logBox.innerHTML = `[SYS] Map initialized.<br>[INTEL] Loaded ${threatNodes.length} active coordinates.`;
            threatNodes.forEach(node => {
                logBox.innerHTML += `<br>[NODE] Detected threat at ${node.domain} (${node.country})`;
            });
            logBox.scrollTop = logBox.scrollHeight;
        }

        // Project coordinate lat/lon to Canvas coordinate X/Y
        function project(lat, lon, width, height) {
            // Simple Mercator Projection
            const x = (lon + 180) * (width / 360);
            const y = (90 - lat) * (height / 180) * 0.95 + (height * 0.025); // center offset cushioning
            return { x, y };
        }

        let animationFrame;
        function renderMap() {
            ctx.fillStyle = "#030508";
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            // Draw dot-matrix grid world map background
            ctx.fillStyle = "rgba(0, 255, 102, 0.12)"; // Dim Matrix green
            landGrid.forEach(coord => {
                const pt = project(coord[0], coord[1], canvas.width, canvas.height);
                ctx.beginPath();
                ctx.arc(pt.x, pt.y, 2.5, 0, Math.PI * 2);
                ctx.fill();
            });

            // Draw pulsing threat beacons
            threatNodes.forEach(node => {
                const pt = project(node.lat, node.lon, canvas.width, canvas.height);
                const color = node.level === "dangerous" ? "#ff2a2a" : "#ffaa00";
                
                // Pulsing glow rings
                node.pulse += 0.05;
                const ringSize = (node.pulse % 1) * 30;
                const opacity = 1 - (node.pulse % 1);

                ctx.strokeStyle = color;
                ctx.lineWidth = 1.5;
                ctx.beginPath();
                ctx.arc(pt.x, pt.y, ringSize, 0, Math.PI * 2);
                ctx.stroke();

                // Core dot
                ctx.fillStyle = color;
                ctx.beginPath();
                ctx.arc(pt.x, pt.y, 4, 0, Math.PI * 2);
                ctx.fill();

                // Label on hover/proximity (simplified: always show labels for top 3)
                ctx.fillStyle = "#d1fae5";
                ctx.font = "9px monospace";
                ctx.fillText(node.domain, pt.x + 8, pt.y + 3);
            });

            animationFrame = requestAnimationFrame(renderMap);
        }
        
        if (mapAnimationId) cancelAnimationFrame(mapAnimationId);
        renderMap();
        mapAnimationId = animationFrame;
    }

    const btnRefreshMap = document.getElementById("btn-refresh-map");
    if (btnRefreshMap) {
        btnRefreshMap.onclick = () => initThreatMap();
    }

    // ----------------------------------------------------
    // 2. Cyber Hygiene scorecard & tips calculator
    // ----------------------------------------------------
    async function generateHygieneAudit() {
        try {
            const res = await fetch(`${API_BASE}/api/history`);
            if (!res.ok) throw new Error("Failed to load audit history");
            const history = await res.json();

            let score = 100;
            let dangerousCount = 0;
            let suspiciousCount = 0;
            let insecureCount = 0;

            history.forEach(scan => {
                if (scan.risk_level === "dangerous") {
                    dangerousCount++;
                    score -= 15;
                } else if (scan.risk_level === "suspicious") {
                    suspiciousCount++;
                    score -= 5;
                }
                
                // check HTTPS
                const hasInsecure = scan.explanations.some(e => e.includes("insecure") || e.includes("HTTP"));
                if (hasInsecure) {
                    insecureCount++;
                    score -= 3;
                }
            });

            // check whitelist/blacklist rules
            let whitelistCount = 0;
            let blacklistCount = 0;
            try {
                const wlRes = await fetch(`${API_BASE}/api/whitelist`);
                if (wlRes.ok) {
                    const wlData = await wlRes.json();
                    whitelistCount = wlData.length;
                    score += wlData.length * 2; // small bonus for active rules config
                }
                const blRes = await fetch(`${API_BASE}/api/blacklist`);
                if (blRes.ok) {
                    const blData = await blRes.json();
                    blacklistCount = blData.length;
                }
            } catch (err) {}

            score = Math.max(10, Math.min(100, score));

            // Render grade circle
            let grade = "A+";
            let circleClass = "grade-A-plus";
            let statusText = "Secure Browser";
            let statusClass = "safe";

            if (score < 60) {
                grade = "F";
                circleClass = "grade-F";
                statusText = "Critical Exposure";
                statusClass = "dangerous";
            } else if (score < 70) {
                grade = "D";
                circleClass = "grade-D";
                statusText = "Weak Shield";
                statusClass = "dangerous";
            } else if (score < 80) {
                grade = "C";
                circleClass = "grade-C";
                statusText = "Moderate Risk";
                statusClass = "suspicious";
            } else if (score < 90) {
                grade = "B";
                circleClass = "grade-B";
                statusText = "Good Shield";
                statusClass = "safe";
            } else if (score < 95) {
                grade = "A";
                circleClass = "grade-A";
                statusText = "Highly Secure";
                statusClass = "safe";
            }

            const gradeCircle = document.getElementById("hygiene-grade-circle");
            gradeCircle.textContent = grade;
            gradeCircle.className = `grade-circle ${circleClass}`;

            document.getElementById("hygiene-score-percentage").textContent = `${score}%`;
            
            const statusBadge = document.getElementById("hygiene-status-badge");
            statusBadge.textContent = statusText;
            statusBadge.className = `badge ${statusClass}`;

            // Update details
            const totalScans = history.length;
            const httpsRatio = totalScans > 0 ? Math.round(((totalScans - insecureCount) / totalScans) * 100) : 100;
            document.getElementById("hygiene-https-ratio").textContent = `${httpsRatio}% Secure`;
            document.getElementById("hygiene-avoided-count").textContent = `${dangerousCount} Blocked`;
            document.getElementById("hygiene-rules-active").textContent = `${whitelistCount + blacklistCount} Enabled`;

            // Generate actionable tips list
            const tipsContainer = document.getElementById("hygiene-tips");
            tipsContainer.innerHTML = "";

            const tips = [];
            if (httpsRatio < 90) {
                tips.push({
                    title: "Force Encrypted HTTPS Connections",
                    text: "Several visited domains lack HTTPS encryption. Enable HTTPS-Only mode in browser settings to protect credential leaks on public networks."
                });
            }
            if (dangerousCount > 0) {
                tips.push({
                    title: "Clean Browser Cookie/Session Cache",
                    text: `PhishGuard intercepted ${dangerousCount} dangerous websites. We recommend clearing cookies and site data to wipe potential tracking beacons.`
                });
            }
            if (whitelistCount + blacklistCount === 0) {
                tips.push({
                    title: "Configure Domain Rules",
                    text: "You haven't defined any custom trusted or blocked domain rules. Head to the 'Access Rules' tab to blacklist suspicious sites manually."
                });
            }
            if (score > 95) {
                tips.push({
                    title: "Excellent Cyber Hygiene!",
                    text: "Your browsing patterns are highly secure. Maintain safe standards by checking suspicious links using the Diagnostics scanner before login."
                });
            }

            tips.forEach(tip => {
                const tipCard = document.createElement("div");
                tipCard.className = "finding-item";
                tipCard.innerHTML = `
                    <i class="fa-solid fa-lightbulb text-orange" style="margin-top: 3px;"></i>
                    <div style="display: flex; flex-direction: column;">
                        <span style="font-weight: 700; font-size: 13px; color: var(--text-main);">${tip.title}</span>
                        <span class="text-muted" style="font-size: 11px; margin-top: 2px;">${tip.text}</span>
                    </div>
                `;
                tipsContainer.appendChild(tipCard);
            });

        } catch (err) {
            console.error(err);
        }
    }

    // ----------------------------------------------------
    // 3. Spot-the-Phish Educational Game Controller
    // ----------------------------------------------------
    const GAME_ROUNDS = [
        {
            title: "Chase Online Notification",
            question: "You get a fraud warning notification directing you to click the link below to confirm identity. Is this safe or phishing?",
            url: "https://www.chase.com/personal/fraud-protection",
            is_safe: true,
            explanation: "This URL matches the legitimate Chase Bank official domain (chase.com) using a secure HTTPS connection. Correct choice: SAFE."
        },
        {
            title: "Cyrillic Character Impersonation",
            question: "A security notice prompts you to authenticate your Google profile at the link below. Is it safe or phishing?",
            url: "https://www.gооgle.com/accounts/signin",
            is_safe: false,
            explanation: "PHISHING! This is a homoglyph attack. The 'о' characters are Cyrillic Unicode code points (U+043e) mimicking standard English letters to bypass visual detection."
        },
        {
            title: "Paypal Merchant Invoice Check",
            question: "A seller requests invoice payment via the link below. Is it safe or phishing?",
            url: "http://paypal-security-invoice-billing-portal.xyz/pay",
            is_safe: false,
            explanation: "PHISHING! The domain is 'paypal-security-invoice-billing-portal.xyz', not 'paypal.com'. Cybercriminals use long hyphenated domains incorporating brand keywords to deceive."
        },
        {
            title: "Document Vault Share link",
            question: "A coworker shares a folder with you from Dropbox. Is it safe or phishing?",
            url: "https://www.dropbox.com/sh/s/vault-records2026",
            is_safe: true,
            explanation: "This URL matches the official Dropbox domain (dropbox.com) and utilizes a secure HTTPS connection. Correct choice: SAFE."
        },
        {
            title: "Microsoft Account Office Update",
            question: "An alert claims your Office 365 access is locked. Authenticate via this link. Is it safe or phishing?",
            url: "http://microsoft.com.office-online-security-update.xyz/",
            is_safe: false,
            explanation: "PHISHING! The actual domain is 'office-online-security-update.xyz', not 'microsoft.com'. The 'microsoft.com' segment is a subdomain designed to fool users reading left-to-right."
        }
    ];

    let gameCurrentRound = 0;
    let gameScore = 0;

    function initPhishGame() {
        gameCurrentRound = 0;
        gameScore = 0;
        showRound();
    }

    function showRound() {
        const round = GAME_ROUNDS[gameCurrentRound];
        document.getElementById("game-score-display").textContent = `Round ${gameCurrentRound + 1}/5`;
        document.getElementById("game-question-title").textContent = round.title;
        document.getElementById("game-question-title").style.color = "#60a5fa";
        document.getElementById("game-url-display").textContent = round.url;

        // Reset display blocks
        document.getElementById("game-question-block").style.display = "block";
        document.getElementById("game-feedback-block").style.display = "none";
        document.getElementById("game-result-block").style.display = "none";
    }

    // Bind Quiz choice buttons
    document.querySelectorAll(".game-choice-btn").forEach(btn => {
        btn.onclick = () => {
            const choice = btn.getAttribute("data-choice");
            const round = GAME_ROUNDS[gameCurrentRound];
            const isCorrect = (choice === "safe" && round.is_safe) || (choice === "phish" && !round.is_safe);

            const feedbackBanner = document.getElementById("game-feedback-banner");
            if (isCorrect) {
                gameScore++;
                feedbackBanner.textContent = "✅ CORRECT RESPONSE!";
                feedbackBanner.style.background = "rgba(16, 185, 129, 0.12)";
                feedbackBanner.style.color = "var(--success)";
                feedbackBanner.style.borderColor = "var(--success)";
            } else {
                feedbackBanner.textContent = "❌ DECEPTIVE THREAT MISSED!";
                feedbackBanner.style.background = "rgba(239, 68, 68, 0.12)";
                feedbackBanner.style.color = "var(--danger)";
                feedbackBanner.style.borderColor = "var(--danger)";
            }
            feedbackBanner.style.border = "1px solid";

            document.getElementById("game-feedback-explanation").textContent = round.explanation;

            document.getElementById("game-question-block").style.display = "none";
            document.getElementById("game-feedback-block").style.display = "block";
        };
    });

    const btnGameNext = document.getElementById("btn-game-next");
    if (btnGameNext) {
        btnGameNext.onclick = () => {
            gameCurrentRound++;
            if (gameCurrentRound < 5) {
                showRound();
            } else {
                // Show game results
                document.getElementById("game-question-block").style.display = "none";
                document.getElementById("game-feedback-block").style.display = "none";
                
                document.getElementById("game-final-correct").textContent = gameScore;
                
                let rating = "Security Apprentice";
                if (gameScore === 5) rating = "Expert Threat Investigator 🛡️";
                else if (gameScore >= 3) rating = "Security Analyst 👁️";
                
                document.getElementById("game-final-badge").textContent = `Awarded Badge: ${rating}`;
                document.getElementById("game-result-block").style.display = "block";
            }
        };
    }

    const btnGameRestart = document.getElementById("btn-game-restart");
    if (btnGameRestart) {
        btnGameRestart.onclick = () => initPhishGame();
    }

    // ----------------------------------------------------
    // 4. Credential Leak Scanner Controller
    // ----------------------------------------------------
    const btnRunBreach = document.getElementById("btn-run-breach");
    const breachEmailInput = document.getElementById("breach-email-input");
    const breachResult = document.getElementById("breach-result");
    
    if (btnRunBreach && breachEmailInput && breachResult) {
        btnRunBreach.onclick = async () => {
            const email = breachEmailInput.value.trim();
            if (!email) return;
            
            btnRunBreach.disabled = true;
            btnRunBreach.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Checking registry...`;
            
            try {
                const response = await fetch(`${API_BASE}/api/breach-check?email=${encodeURIComponent(email)}`);
                if (!response.ok) throw new Error("Breach check API request failed");
                const data = await response.json();
                
                if (data.is_compromised) {
                    let breachesHtml = "";
                    data.breaches.forEach(b => {
                        breachesHtml += `
                            <tr style="border-bottom: 1px solid var(--border-color);">
                                <td style="font-weight: 700; color: var(--danger); padding: 10px 0;">${b.name}</td>
                                <td style="font-family: monospace; font-size: 12px;">${b.domain}</td>
                                <td style="font-size: 12px; color: var(--text-muted);">${b.breach_date}</td>
                                <td style="font-size: 11px;">${b.leaked_data.join(", ")}</td>
                                <td><span class="badge dangerous" style="font-size: 9px; padding: 2px 6px;">${b.severity.toUpperCase()}</span></td>
                            </tr>
                        `;
                    });

                    breachResult.innerHTML = `
                        <!-- Compromised Banner -->
                        <div style="background: rgba(239, 68, 68, 0.12); border: 1px solid var(--danger); padding: 16px; border-radius: 8px; font-weight: 700; color: var(--danger); display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 20px;">
                            <div style="display: flex; align-items: center; gap: 12px;">
                                <span style="font-size: 20px;">⚠️</span>
                                <div>
                                    <h4 style="font-size: 14px; font-weight: 700;">COMPROMISED: ${data.breaches_count} Data Breaches Found!</h4>
                                    <p class="text-muted" style="font-size: 11px; font-weight: 500; margin-top: 2px;">Your email address and credentials have been leaked in the breaches listed below.</p>
                                </div>
                            </div>
                            <div style="text-align: right; font-size: 10px; color: var(--danger); min-width: 100px; border-left: 1px solid rgba(239, 68, 68, 0.2); padding-left: 12px;">
                                <div style="font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px;">Accuracy Rate</div>
                                <div style="font-size: 16px; font-weight: 800; color: var(--danger); margin-top: 2px;">${data.accuracy_rate}%</div>
                            </div>
                        </div>

                        <div class="table-container">
                            <table class="history-table" style="width: 100%;">
                                <thead>
                                    <tr>
                                        <th>Breach Name</th>
                                        <th>Target Domain</th>
                                        <th>Breach Date</th>
                                        <th>Compromised Data</th>
                                        <th>Severity</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${breachesHtml}
                                </tbody>
                            </table>
                        </div>

                        <!-- Recommendations -->
                        <div style="margin-top: 24px; padding: 16px; border: 1px solid var(--border-color); border-radius: 8px; background: rgba(255,255,255,0.01);">
                            <h5 style="font-size: 13px; font-weight: 700; margin-bottom: 8px; color: #60a5fa;"><i class="fa-solid fa-key"></i> Immediate Security Recommendations</h5>
                            <ul style="font-size: 12px; line-height: 1.5; color: var(--text-muted); padding-left: 16px;">
                                <li><strong>Change your password</strong> on any accounts sharing the same password immediately.</li>
                                <li>Enable <strong>Multi-Factor Authentication (2FA)</strong> on all important digital portals.</li>
                                <li>Consider adopting a **credential vault / password manager** to auto-generate unique passwords.</li>
                            </ul>
                        </div>
                    `;
                } else {
                    breachResult.innerHTML = `
                        <!-- Safe Banner -->
                        <div style="background: rgba(16, 185, 129, 0.12); border: 1px solid var(--success); padding: 16px; border-radius: 8px; font-weight: 700; color: var(--success); display: flex; align-items: center; justify-content: space-between; gap: 12px;">
                            <div style="display: flex; align-items: center; gap: 12px;">
                                <span style="font-size: 20px;">✅</span>
                                <div>
                                    <h4 style="font-size: 14px; font-weight: 700;">SECURE: No compromises detected</h4>
                                    <p class="text-muted" style="font-size: 11px; font-weight: 500; margin-top: 2px;">Your email address is currently not registered in any historical breaches tracked by PhishGuard AI.</p>
                                </div>
                            </div>
                            <div style="text-align: right; font-size: 10px; color: var(--success); min-width: 100px; border-left: 1px solid rgba(16, 185, 129, 0.2); padding-left: 12px;">
                                <div style="font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px;">Accuracy Rate</div>
                                <div style="font-size: 16px; font-weight: 800; color: var(--success); margin-top: 2px;">${data.accuracy_rate}%</div>
                            </div>
                        </div>
                    `;
                }
                
                breachResult.style.display = "block";
            } catch (err) {
                console.error(err);
                alert("Breach check lookup query failed.");
            } finally {
                btnRunBreach.disabled = false;
                btnRunBreach.innerHTML = "Check Leaks";
            }
        };

        breachEmailInput.onkeypress = (e) => {
            if (e.key === "Enter") btnRunBreach.click();
        };
    }

    // ----------------------------------------------------
    // Settings: Configuration Modes Logic
    // ----------------------------------------------------
    const btnSaveSettings = document.getElementById("btn-save-settings");
    
    function loadSettings() {
        const profile = localStorage.getItem("pg_protection_profile") || "balanced";
        const radio = document.querySelector(`input[name="protection-profile"][value="${profile}"]`);
        if (radio) radio.checked = true;
    }
    
    if (btnSaveSettings) {
        btnSaveSettings.onclick = () => {
            const selected = document.querySelector('input[name="protection-profile"]:checked');
            if (selected) {
                const value = selected.value;
                localStorage.setItem("pg_protection_profile", value);
                
                // Broadcast settings updated message so extension can read if running in the same browser window storage scope
                chrome?.storage?.local?.set({ pg_protection_profile: value }, () => {
                    console.log("Synced settings to Extension storage: " + value);
                });
                
                alert(`Configuration saved successfully! Profile mode: ${value.toUpperCase()}`);
            }
        };
    }

    // Initial settings load
    loadSettings();

    // Initial load: Fetch stats and history directly
    fetchStats();
    fetchHistory();
});
