// CyberSec AI Dashboard — v3.2.0
// Real-time progressive streaming for Findings, Patches, Message Bus, and Reports.

document.addEventListener("DOMContentLoaded", () => {
    let currentJobId = null;
    let ws = null;
    let pollingInterval = null;
    let latestReportMarkdown = "";

    // Maps for incremental deduplicated tracking
    const confirmedFindingsMap = new Map();
    const candidateFindingsMap = new Map();
    const fixesMap = new Map();
    let currentFindingFilter = "all";
    let messageCount = 0;

    // ── Mermaid v10 Configuration ──
    try {
        if (window.mermaid) {
            mermaid.initialize({
                startOnLoad: false,
                theme: "dark",
                securityLevel: "loose",
                themeVariables: {
                    primaryColor: "#0d1a2e",
                    primaryTextColor: "#00fff7",
                    primaryBorderColor: "#00fff7",
                    lineColor: "#b845ff",
                    secondaryColor: "#080f1f",
                    tertiaryColor: "#050a14",
                    edgeLabelBackground: "#080f1f",
                    background: "#050a14"
                }
            });
        }
    } catch (e) {
        console.warn("Mermaid init:", e);
    }

    // ── Marked.js Configuration ──
    if (window.marked) {
        marked.setOptions({
            gfm: true,
            breaks: true,
            headerIds: true,
            mangle: false
        });
    }

    // ── DOM References ──
    const btnStart          = document.getElementById("btn-start");
    const inputRepo         = document.getElementById("target-repo");
    const selectEngine      = document.getElementById("engine-select");
    const statusBar         = document.getElementById("status-bar");
    const jobIdDisp         = document.getElementById("job-id-disp");
    const jobStatusBadge    = document.getElementById("job-status-badge");
    const statConfirmed     = document.getElementById("stat-confirmed");
    const statEscalated     = document.getElementById("stat-escalated");
    const statDuration      = document.getElementById("stat-duration");
    const terminalLog       = document.getElementById("terminal-log");
    const terminalMsgCount  = document.getElementById("terminal-msg-count");
    const globalPulse       = document.getElementById("global-pulse");
    const globalStatusTxt   = document.getElementById("global-status-text");
    const themeToggle       = document.getElementById("theme-toggle");
    const btnClearTerminal  = document.getElementById("btn-clear-terminal");
    const findingsList      = document.getElementById("findings-list");
    const fixesList         = document.getElementById("fixes-list");
    const reportView        = document.getElementById("report-view");
    const btnCopyReport     = document.getElementById("btn-copy-report");
    const btnDownloadReport = document.getElementById("btn-download-report");
    const btnPrintReport    = document.getElementById("btn-print-report");
    const btnRefreshDiagram = document.getElementById("btn-refresh-diagram");
    const findingsFilterBar = document.getElementById("findings-filter");

    // ── Theme Management ──
    const root = document.documentElement;
    const savedTheme = localStorage.getItem("cybersec-theme") || "dark";
    root.setAttribute("data-theme", savedTheme);

    if (themeToggle) {
        themeToggle.addEventListener("click", () => {
            const current = root.getAttribute("data-theme");
            const next = current === "dark" ? "light" : "dark";
            root.setAttribute("data-theme", next);
            localStorage.setItem("cybersec-theme", next);
            if (currentJobId) {
                fetchDiagram(currentJobId);
            }
        });
    }

    // ── Tab Navigation ──
    const tabButtons = document.querySelectorAll(".tab-nav__btn");
    const tabPanes   = document.querySelectorAll(".tab-pane");

    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            tabButtons.forEach(b => {
                b.classList.remove("active");
                b.setAttribute("aria-selected", "false");
            });
            tabPanes.forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            btn.setAttribute("aria-selected", "true");
            const pane = document.getElementById(btn.dataset.tab);
            if (pane) pane.classList.add("active");

            // If switching to diagram tab, ensure diagram is rendered
            if (btn.dataset.tab === "tab-diagram") {
                if (currentJobId) {
                    fetchDiagram(currentJobId);
                } else {
                    renderDiagram();
                }
            }
        });
    });

    // ── Terminal Clear ──
    if (btnClearTerminal) {
        btnClearTerminal.addEventListener("click", () => {
            terminalLog.innerHTML = "";
            messageCount = 0;
            if (terminalMsgCount) terminalMsgCount.textContent = "0 msgs";
            appendRawTerminal('<span class="term-prompt">root@cybersec-ai:~$</span> Terminal cleared.');
        });
    }

    // ── Findings Severity Filter ──
    if (findingsFilterBar) {
        findingsFilterBar.addEventListener("click", (e) => {
            const pill = e.target.closest(".filter-pill");
            if (!pill) return;
            findingsFilterBar.querySelectorAll(".filter-pill").forEach(p => p.classList.remove("active"));
            pill.classList.add("active");
            currentFindingFilter = pill.dataset.filter || "all";
            applyFindingsFilter();
        });
    }

    function applyFindingsFilter() {
        const cards = findingsList.querySelectorAll(".finding-card");
        cards.forEach(card => {
            const sev = (card.dataset.severity || "").toUpperCase();
            if (currentFindingFilter === "all" || sev === currentFindingFilter.toUpperCase()) {
                card.style.display = "";
            } else {
                card.style.display = "none";
            }
        });
    }

    // ── Report Actions (Copy, Download, Print) ──
    if (btnCopyReport) {
        btnCopyReport.addEventListener("click", async () => {
            if (!latestReportMarkdown) {
                alert("No report generated yet.");
                return;
            }
            try {
                await navigator.clipboard.writeText(latestReportMarkdown);
                const prev = btnCopyReport.textContent;
                btnCopyReport.textContent = "✓ Copied!";
                setTimeout(() => { btnCopyReport.textContent = prev; }, 2000);
            } catch (err) {
                alert("Failed to copy: " + err);
            }
        });
    }

    if (btnDownloadReport) {
        btnDownloadReport.addEventListener("click", () => {
            if (!latestReportMarkdown) {
                alert("No report generated yet.");
                return;
            }
            const blob = new Blob([latestReportMarkdown], { type: "text/markdown;charset=utf-8" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `security_report_${currentJobId || "scan"}.md`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        });
    }

    if (btnPrintReport) {
        btnPrintReport.addEventListener("click", () => {
            window.print();
        });
    }

    if (btnRefreshDiagram) {
        btnRefreshDiagram.addEventListener("click", () => {
            if (currentJobId) fetchDiagram(currentJobId);
        });
    }

    // ── Scan Launch ──
    btnStart.addEventListener("click", async () => {
        const repo = inputRepo.value.trim();
        const engine = selectEngine.value;
        if (!repo) {
            alert("Please enter a target repository path or URL.");
            return;
        }

        btnStart.disabled = true;
        btnStart.querySelector(".btn-scan__text").textContent = "⏳ Initializing…";
        terminalLog.innerHTML = "";
        messageCount = 0;
        if (terminalMsgCount) terminalMsgCount.textContent = "0 msgs";

        appendRawTerminal('<span class="term-prompt">root@cybersec-ai:~$</span> Submitting scan job to API manager…');
        resetUIState();
        setPipelineStatus("running");

        try {
            const resp = await fetch("/api/jobs", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ target_repo: repo, engine: engine })
            });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const jobData = await resp.json();
            currentJobId = jobData.job_id;

            jobIdDisp.textContent = currentJobId.slice(0, 14) + "…";
            statusBar.classList.remove("hidden");
            updateJobBadge(jobData.status);

            connectWebSocket(currentJobId);
            startPolling(currentJobId);
        } catch (err) {
            appendRawTerminal(`[ERROR] Failed to launch scan: ${esc(err.message)}`);
            btnStart.disabled = false;
            btnStart.querySelector(".btn-scan__text").textContent = "🚀 Launch Scan";
            setPipelineStatus("idle");
        }
    });

    // ── WebSocket Connection ──
    function connectWebSocket(jobId) {
        if (ws) {
            try { ws.close(); } catch(e) {}
        }
        const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
        ws = new WebSocket(`${proto}//${window.location.host}/api/jobs/${jobId}/ws`);

        ws.onopen = () => {
            appendRawTerminal(`[WS] Connection established · job=${esc(jobId)}`);
        };

        ws.onmessage = (evt) => {
            try {
                const msg = JSON.parse(evt.data);
                handleWSMessage(msg);
            } catch (e) {
                console.error("WS message parse error:", e);
            }
        };

        ws.onerror = (err) => {
            console.warn("WebSocket error:", err);
        };

        ws.onclose = () => {
            appendRawTerminal("[WS] Live message stream closed.");
        };
    }

    // ── Dispatch Incoming WebSocket Events ──
    function handleWSMessage(msg) {
        if (!msg || !msg.event) return;

        switch (msg.event) {
            case "initial_state":
                if (Array.isArray(msg.messages)) {
                    msg.messages.forEach(m => formatAndAppend(m));
                }
                if (msg.status) updateJobBadge(msg.status);
                if (msg.summary) updateStats(msg.summary);
                break;

            case "progress":
            case "bus_message":
                if (msg.message) formatAndAppend(msg.message);
                break;

            case "stage_start":
                setStageRunning(msg.stage);
                appendStageBanner(`▶ STAGE STARTED: ${msg.stage}`);
                break;

            case "stage_done":
                markStageDone(msg.stage);
                appendStageBanner(`✔ STAGE COMPLETED: ${msg.stage}`);
                break;

            case "finding_verified":
                if (msg.finding) {
                    addIncrementalFinding(msg.finding);
                }
                break;

            case "status_change":
            case "job_status":
                updateJobBadge(msg.status);
                if (msg.summary) updateStats(msg.summary);
                if (msg.status === "completed") {
                    setPipelineStatus("done");
                    fetchFinalArtifacts(currentJobId);
                } else if (msg.status === "failed") {
                    setPipelineStatus("error");
                    appendRawTerminal(`[JOB FAILED] ${esc(msg.error || "Unknown execution error")}`);
                }
                break;
        }
    }

    // ── Append Stage Banner to Message Bus ──
    function appendStageBanner(text) {
        const div = document.createElement("div");
        div.className = "term-stage-banner";
        div.textContent = text;
        terminalLog.appendChild(div);
        terminalLog.scrollTop = terminalLog.scrollHeight;
    }

    // ── Format and Append Structured Bus Message ──
    function formatAndAppend(busMsg) {
        if (!busMsg) return;

        messageCount++;
        if (terminalMsgCount) terminalMsgCount.textContent = `${messageCount} msgs`;

        const timeStr = busMsg.timestamp
            ? new Date(busMsg.timestamp * 1000).toLocaleTimeString()
            : new Date().toLocaleTimeString();

        const agentRaw = busMsg.agent || busMsg.sender || "SYS";
        const agent = String(agentRaw).toUpperCase();
        const receiver = busMsg.receiver ? String(busMsg.receiver).toUpperCase() : "";
        const msgType = busMsg.message_type || busMsg.type || "EVENT";
        const pl = busMsg.payload || {};

        let decision = busMsg.decision || pl.decision || "";
        let reason = busMsg.reason || pl.reason || pl.rationale || pl.summary || pl.detail || pl.evidence || "";

        if (!decision && pl.status) decision = pl.status;
        if (!decision && pl.event_type) decision = pl.event_type;
        if (!reason && pl.rule_id) reason = `Rule: ${pl.rule_id} in ${pl.file || ""}:${pl.line || ""}`;

        // Color coding class for agent
        let agentClass = "term-agent-sys";
        const agLow = agent.toLowerCase();
        if (agLow.includes("ingest") || agLow === "m1") agentClass = "term-agent-ingest";
        else if (agLow.includes("detect") || agLow === "m2") agentClass = "term-agent-detect";
        else if (agLow.includes("reason") || agLow === "m3") agentClass = "term-agent-reason";
        else if (agLow.includes("exploit") || agLow === "m4") agentClass = "term-agent-exploit";
        else if (agLow.includes("report") || agLow === "m5") agentClass = "term-agent-report";
        else if (agLow.includes("orchestrator")) agentClass = "term-agent-orchestrator";

        // Build DOM line safely
        const lineEl = document.createElement("div");
        lineEl.className = "term-line";

        let html = `<span class="term-time">[${esc(timeStr)}]</span> `;
        html += `<span class="term-agent ${agentClass}">[${esc(agent)}]</span> `;
        if (receiver) {
            html += `<span class="term-arrow">&rarr;</span> <span class="term-receiver">[${esc(receiver)}]</span> `;
        }
        html += `<span class="term-type">${esc(msgType)}</span> `;
        if (decision) {
            html += `<span class="term-decision">${esc(decision)}</span> `;
        }
        if (reason) {
            html += `<span class="term-reason">&mdash; ${esc(reason)}</span>`;
        }

        lineEl.innerHTML = html;
        terminalLog.appendChild(lineEl);
        terminalLog.scrollTop = terminalLog.scrollHeight;

        // Update sidebar pipeline state
        if (busMsg.decision && agent) {
            updateComponentState(agent, busMsg.decision, reason);
        }
        if (pl.stage && pl.event_type === "START") {
            setStageRunning(pl.stage);
        } else if (pl.stage && pl.event_type === "END") {
            markStageDone(pl.stage);
        }
        if (pl.summary) {
            updateStats(pl.summary);
        }
    }

    function appendRawTerminal(html) {
        const div = document.createElement("div");
        div.className = "term-line";
        div.innerHTML = html;
        terminalLog.appendChild(div);
        terminalLog.scrollTop = terminalLog.scrollHeight;
    }

    // ── Incremental Findings & Patches Handling ──
    function addIncrementalFinding(f) {
        if (!f) return;
        const findingKey = `${f.rule_id || "FINDING"}:${f.file || ""}:${f.line || 0}`;

        // Check if already confirmed
        if (confirmedFindingsMap.has(findingKey)) {
            return;
        }
        confirmedFindingsMap.set(findingKey, f);

        // Remove empty state placeholder if present
        const emptyState = findingsList.querySelector(".empty-state");
        if (emptyState) emptyState.remove();

        // If this finding was previously displayed as a candidate card, remove the candidate card
        const existingCandidateCard = findingsList.querySelector(`[data-candidate-key="${findingKey}"]`);
        if (existingCandidateCard) existingCandidateCard.remove();

        // Render new confirmed finding card
        const card = createFindingCardElement(f, true);
        findingsList.appendChild(card);

        // Update finding count badge
        const badgeCountFindings = document.getElementById("badge-count-findings");
        if (badgeCountFindings) {
            badgeCountFindings.textContent = confirmedFindingsMap.size;
        }

        // Update top metric pill
        if (statConfirmed) {
            statConfirmed.textContent = confirmedFindingsMap.size;
        }

        // If escalated / manual review, increment escalated counter
        const isEscalated = ["MANUAL_REVIEW_REQUIRED", "MANUAL_REVIEW", "ESCALATED"].includes((f.loop_status || "").toUpperCase());
        if (isEscalated && statEscalated) {
            let cur = parseInt(statEscalated.textContent || "0", 10) || 0;
            statEscalated.textContent = cur + 1;
        }

        // Apply severity filter to new card
        applyFindingsFilter();

        // If finding has a patch diff, add it gradually to Fixes tab
        if (f.patch_diff && f.patch_diff.trim()) {
            addIncrementalFix({
                rule_id: f.rule_id,
                vuln_class: f.vuln_class,
                file: f.file,
                line: f.line,
                severity: f.severity,
                explanation: f.explanation,
                patch_diff: f.patch_diff,
                loop_status: f.loop_status,
                confidence: f.confidence
            });
        }
    }

    function addIncrementalFix(fx) {
        const fixKey = `${fx.rule_id || "PATCH"}:${fx.file || ""}:${fx.line || 0}`;
        if (fixesMap.has(fixKey)) return;
        fixesMap.set(fixKey, fx);

        const emptyFixes = fixesList.querySelector(".empty-state");
        if (emptyFixes) emptyFixes.remove();

        const card = createFixCardElement(fx, true);
        fixesList.appendChild(card);

        const badgeCountFixes = document.getElementById("badge-count-fixes");
        if (badgeCountFixes) {
            badgeCountFixes.textContent = fixesMap.size;
        }
    }

    // ── Create Finding Card DOM Element ──
    function createFindingCardElement(f, isNew = false) {
        const div = document.createElement("div");
        div.className = `finding-card ${isNew ? "finding-card--new" : ""}`;
        div.dataset.severity = (f.severity || "MEDIUM").toUpperCase();

        const sevCls = getSevClass(f.severity);
        const statusTag = f.loop_status === "ACCEPTED"
            ? '<span class="tier-badge tier-verified-full">✓ Fixed &amp; Verified</span>'
            : (f.loop_status ? `<span class="tier-badge tier-unverified">${esc(f.loop_status)}</span>` : "");
        const exploitTag = f.exploit_verdict
            ? `<span class="tier-badge tier-verified-narrow">Exploit: ${esc(f.exploit_verdict)}</span>`
            : "";

        div.innerHTML = `
            <div class="card-top">
                <span class="vuln-title"><strong>${esc(f.rule_id || "FINDING")}</strong>: ${esc(f.vuln_class || "Vulnerability")}</span>
                <div class="badge-tags">
                    <span class="badge ${sevCls}">${esc(f.severity || "UNKNOWN")}</span>
                    ${statusTag}${exploitTag}
                    <span class="loc-tag">${esc(f.file || "")}:${f.line || 0}</span>
                </div>
            </div>
            <div class="card-desc"><strong>Analysis Reasoning:</strong> ${esc(f.confirmation_reasoning || f.explanation || "Vulnerability confirmed by security reasoning agent.")}</div>
            ${f.remediation_advice ? `<div class="card-subtext" style="color:var(--neon-amber)"><strong>Remediation Advice:</strong> ${esc(f.remediation_advice)}</div>` : ""}
        `;
        return div;
    }

    // ── Create Fix Card DOM Element ──
    function createFixCardElement(fx, isNew = false) {
        const div = document.createElement("div");
        div.className = `fix-card ${isNew ? "fix-card--new" : ""}`;

        const conf = fx.confidence || { tier: "unverified", reason: "Automated patch" };
        let tierCls = "tier-unverified", tierLabel = "unverified → MANUAL_REVIEW";
        if (conf.tier === "verified_full") {
            tierCls = "tier-verified-full";
            tierLabel = "verified_full (sandbox tested)";
        } else if (conf.tier === "verified_narrow") {
            tierCls = "tier-verified-narrow";
            tierLabel = "verified_narrow";
        }

        const diffLines = (fx.patch_diff || "").split("\n").map(ln => {
            if (ln.startsWith("+")) return `<span class="add">${esc(ln)}</span>`;
            if (ln.startsWith("-")) return `<span class="del">${esc(ln)}</span>`;
            return esc(ln);
        }).join("\n");

        div.innerHTML = `
            <div class="card-top">
                <span class="vuln-title"><strong>${esc(fx.rule_id || "PATCH")}</strong> &mdash; Automated Sandbox Fix</span>
                <div class="badge-tags">
                    <span class="tier-badge ${tierCls}">${esc(tierLabel)}</span>
                    <span class="loc-tag">${esc(fx.file || "")}:${fx.line || 0}</span>
                </div>
            </div>
            ${conf.reason ? `<div class="card-subtext"><strong>Verification Logic:</strong> ${esc(conf.reason)}</div>` : ""}
            <div class="diff-box">${diffLines}</div>
        `;
        return div;
    }

    // ── Render Candidates (Shown immediately when M2 pattern scan completes) ──
    function renderCandidatesIfNoConfirmed(candidates) {
        if (!candidates || !candidates.length || confirmedFindingsMap.size > 0) return;

        candidates.forEach(c => {
            const candidateKey = `${c.rule_id || "CAND"}:${c.file || ""}:${c.line || 0}`;
            if (candidateFindingsMap.has(candidateKey) || confirmedFindingsMap.has(candidateKey)) return;
            candidateFindingsMap.set(candidateKey, c);

            const emptyState = findingsList.querySelector(".empty-state");
            if (emptyState) emptyState.remove();

            const card = document.createElement("div");
            card.className = "finding-card candidate-card finding-card--new";
            card.dataset.candidateKey = candidateKey;
            card.dataset.severity = (c.severity || "MEDIUM").toUpperCase();

            card.innerHTML = `
                <div class="card-top">
                    <span class="vuln-title"><strong>${esc(c.rule_id || "CANDIDATE")}</strong>: ${esc(c.vuln_class || "Potential Vulnerability")}</span>
                    <div class="badge-tags">
                        <span class="tier-badge tier-unverified"><span class="candidate-pulse"></span>Analyzing in M3 Sandbox...</span>
                        <span class="badge ${getSevClass(c.severity)}">${esc(c.severity || "MEDIUM")}</span>
                        <span class="loc-tag">${esc(c.file || "")}:${c.line || 0}</span>
                    </div>
                </div>
                <div class="card-desc" style="color:var(--text-muted)">AST pattern matched candidate &mdash; reasoning agent is currently analyzing and attempting an automated patch.</div>
            `;
            findingsList.appendChild(card);
        });
        applyFindingsFilter();
    }

    // ── Polling Loop ──
    function startPolling(jobId) {
        if (pollingInterval) clearInterval(pollingInterval);

        pollingInterval = setInterval(async () => {
            if (!jobId || jobId !== currentJobId) {
                clearInterval(pollingInterval);
                return;
            }
            try {
                // 1. Status check
                const r = await fetch(`/api/jobs/${jobId}`);
                if (!r.ok) return;
                const data = await r.json();

                updateJobBadge(data.status);

                if (data.created_at && statDuration) {
                    const elapsed = data.completed_at
                        ? (data.completed_at - data.created_at)
                        : (Date.now() / 1000 - data.created_at);
                    if (!data.result_summary || data.result_summary.duration_seconds === undefined) {
                        statDuration.textContent = `${Math.max(0, elapsed).toFixed(1)}s`;
                    }
                }
                if (data.result_summary) updateStats(data.result_summary);

                // 2. Poll findings & fixes gradually during execution
                if (data.status === "running") {
                    await fetchIncrementalArtifacts(jobId);
                }

                // 3. Completion
                if (data.status === "completed" || data.status === "failed") {
                    clearInterval(pollingInterval);
                    btnStart.disabled = false;
                    btnStart.querySelector(".btn-scan__text").textContent = "🚀 Launch Scan";
                    setPipelineStatus(data.status === "completed" ? "done" : "error");
                    await fetchFinalArtifacts(jobId);
                }
            } catch (e) {
                console.error("Polling error:", e);
            }
        }, 1200);
    }

    // ── Incremental Artifact Fetching ──
    async function fetchIncrementalArtifacts(jobId) {
        try {
            const fRes = await fetch(`/api/jobs/${jobId}/findings`);
            if (fRes.ok) {
                const fData = await fRes.json();
                if (Array.isArray(fData.confirmed)) {
                    fData.confirmed.forEach(f => addIncrementalFinding(f));
                }
                if (Array.isArray(fData.candidates)) {
                    renderCandidatesIfNoConfirmed(fData.candidates);
                }
            }

            const fxRes = await fetch(`/api/jobs/${jobId}/fixes`);
            if (fxRes.ok) {
                const fxData = await fxRes.json();
                if (Array.isArray(fxData)) {
                    fxData.forEach(fx => addIncrementalFix(fx));
                }
            }
        } catch (e) {
            console.warn("Incremental fetch error:", e);
        }
    }

    // ── Fetch Final Artifacts on Job Completion ──
    async function fetchFinalArtifacts(jobId) {
        try {
            const [fRes, fxRes, rRes, dRes] = await Promise.all([
                fetch(`/api/jobs/${jobId}/findings`),
                fetch(`/api/jobs/${jobId}/fixes`),
                fetch(`/api/jobs/${jobId}/report`),
                fetch(`/api/jobs/${jobId}/diagram`)
            ]);

            if (fRes.ok) {
                const d = await fRes.json();
                if (Array.isArray(d.confirmed)) {
                    d.confirmed.forEach(f => addIncrementalFinding(f));
                }
            }
            if (fxRes.ok) {
                const d = await fxRes.json();
                if (Array.isArray(d)) {
                    d.forEach(fx => addIncrementalFix(fx));
                }
            }
            if (rRes.ok) {
                const d = await rRes.json();
                renderReport(d.report || "");
            }
            if (dRes.ok) {
                const d = await dRes.json();
                renderDiagram(d.diagram || "");
            }

            // Ensure all M1-M5 pipeline cards reflect completed status
            const defaults = [
                "Codebase indexed and AST parsed.",
                "AST security patterns inspected.",
                "Review & sandbox verification loop finished.",
                "Exploit verification complete.",
                "Cryptographic report synthesized."
            ];
            ["m1","m2","m3","m4","m5"].forEach((num, i) => {
                const badge = document.getElementById(`${num}-badge`);
                if (badge && (badge.textContent === "PENDING" || badge.textContent === "RUNNING")) {
                    ["run","obs","dec"].forEach(s => setStep(num, s, "done"));
                    badge.textContent = "COMPLETED";
                    badge.className   = "agent-badge badge-completed";
                    const note = document.getElementById(`${num}-note`);
                    if (note && note.textContent.startsWith("Awaiting")) {
                        note.textContent = defaults[i];
                    }
                }
            });
        } catch (e) {
            console.error("Final artifacts fetch error:", e);
        }
    }

    // ── Fetch Diagram On Demand ──
    async function fetchDiagram(jobId) {
        try {
            const res = await fetch(`/api/jobs/${jobId}/diagram`);
            if (res.ok) {
                const data = await res.json();
                renderDiagram(data.diagram || "");
            }
        } catch (e) {
            console.warn("Diagram fetch error:", e);
        }
    }

    // ── Render Report with Marked.js ──
    function renderReport(markdownText) {
        latestReportMarkdown = markdownText || "";
        if (!markdownText || !markdownText.trim()) {
            reportView.innerHTML = `
                <div class="empty-state">
                    <div class="empty-icon">📄</div>
                    <p>No report generated yet &mdash; run a scan to produce an audit report.</p>
                </div>
            `;
            return;
        }

        if (window.marked) {
            try {
                reportView.innerHTML = marked.parse(markdownText);
            } catch (err) {
                console.warn("Marked parse error:", err);
                reportView.innerHTML = `<pre class="font-mono">${esc(markdownText)}</pre>`;
            }
        } else {
            reportView.innerHTML = `<pre class="font-mono">${esc(markdownText)}</pre>`;
        }
    }

    // ── Render Mermaid LangGraph Diagram ──
    async function renderDiagram(diagramDsl) {
        const container = document.getElementById("mermaid-container");
        if (!container || !window.mermaid) return;

        let dsl = (diagramDsl || "").trim();

        // Clean YAML frontmatter if returned by draw_mermaid
        if (dsl.startsWith("---")) {
            const secondYaml = dsl.indexOf("---", 3);
            if (secondYaml !== -1) {
                dsl = dsl.slice(secondYaml + 3).trim();
            }
        }

        // Clean tags that break Mermaid v10 strict parser
        dsl = dsl.replace(/<p>/g, "").replace(/<\/p>/g, "").replace(/&nbsp;/g, " ");

        // If the diagram text is missing or too short, supply rich styled LangGraph flow
        if (!dsl || dsl.length < 15) {
            dsl = `flowchart TD
    classDef stage fill:#0d1a2e,stroke:#00fff7,stroke-width:1.5px,color:#00fff7;
    classDef branch fill:#0d1a2e,stroke:#b845ff,stroke-width:1.5px,color:#b845ff;
    START(["Scan Launch"]):::stage --> M1["M1: Code Ingestion"]:::stage
    M1 --> M2["M2: Pattern Detection"]:::stage
    M2 -- "High Signal Candidates" --> M3["M3: Review & Patch Loop"]:::stage
    M2 -. "Low Signal" .-> NEG["A2A Negotiation"]:::branch
    NEG -. "Accepted" .-> M3
    NEG -. "Declined" .-> M5["M5: Report Synthesis"]:::stage
    M3 --> M4["M4: Exploit Verification"]:::stage
    M4 --> M5
    M5 --> END(["Audit Trail Sealed"]):::stage`;
        } else {
            // Apply neon theme overrides to LangGraph classes
            dsl = dsl.replace(/classDef default fill:#f2f0ff[^\n]*/g, "classDef default fill:#0d1a2e,stroke:#00fff7,stroke-width:1.5px,color:#00fff7;");
            dsl = dsl.replace(/classDef first fill-opacity:0[^\n]*/g, "classDef first fill:#080f1f,stroke:#b845ff,stroke-width:1.5px,color:#b845ff;");
            dsl = dsl.replace(/classDef last fill:#bfb6fc[^\n]*/g, "classDef last fill:#080f1f,stroke:#00ff88,stroke-width:1.5px,color:#00ff88;");
        }

        try {
            const uniqueId = "mermaid-svg-" + Math.floor(Math.random() * 100000);
            const { svg } = await mermaid.render(uniqueId, dsl);
            container.innerHTML = svg;
        } catch (err) {
            console.warn("Primary Mermaid render failed, attempting simplified flow:", err);
            try {
                const cleanDsl = `flowchart TD
    classDef default fill:#0d1a2e,stroke:#00fff7,color:#00fff7;
    START(["Scan Launch"]) --> M1["M1: Ingest"]
    M1 --> M2["M2: Detect"]
    M2 --> M3["M3: Reason & Patch Loop"]
    M3 --> M4["M4: Exploit Verify"]
    M4 --> M5["M5: Report"]
    M5 --> END(["Audit Sealed"])`;
                const id2 = "mermaid-fallback-" + Math.floor(Math.random() * 100000);
                const { svg } = await mermaid.render(id2, cleanDsl);
                container.innerHTML = svg;
            } catch (err2) {
                container.innerHTML = `<pre class="font-mono" style="padding:1rem;color:var(--neon-cyan);">${esc(dsl)}</pre>`;
            }
        }
    }

    // Render initial diagram right away so Graph tab is ready
    renderDiagram();

    // ── Pipeline Status & UI Helpers ──
    function resetUIState() {
        confirmedFindingsMap.clear();
        candidateFindingsMap.clear();
        fixesMap.clear();

        const badgeF = document.getElementById("badge-count-findings");
        if (badgeF) badgeF.textContent = "0";
        const badgeFx = document.getElementById("badge-count-fixes");
        if (badgeFx) badgeFx.textContent = "0";

        findingsList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">⚠️</div>
                <p>Scanning in progress &mdash; findings will stream here gradually.</p>
            </div>
        `;
        fixesList.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🛠️</div>
                <p>Generating patches &mdash; diffs will appear gradually as verified.</p>
            </div>
        `;
        reportView.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📄</div>
                <p>Generating executive report in real-time...</p>
            </div>
        `;

        ["m1","m2","m3","m4","m5"].forEach((num, i) => {
            ["run","obs","dec"].forEach(s => setStep(num, s, ""));
            const b = document.getElementById(`${num}-badge`);
            if (b) { b.textContent = "PENDING"; b.className = "agent-badge"; }
        });
        const notes = [
            "Awaiting job…",
            "Awaiting AST parse…",
            "Awaiting candidates…",
            "Awaiting verify…",
            "Awaiting synthesis…"
        ];
        ["m1","m2","m3","m4","m5"].forEach((num, i) => {
            const n = document.getElementById(`${num}-note`);
            if (n) n.textContent = notes[i];
        });
        document.querySelectorAll(".agent-card").forEach(c => {
            c.classList.remove("active-stage","done-stage");
        });
        if (statConfirmed) statConfirmed.textContent = "0";
        if (statEscalated) statEscalated.textContent = "0";
        if (statDuration)  statDuration.textContent  = "0.0s";
    }

    function setPipelineStatus(state) {
        if (!globalPulse || !globalStatusTxt) return;
        if (state === "running") {
            globalPulse.classList.add("active");
            globalStatusTxt.textContent = "RUNNING";
        } else if (state === "done") {
            globalPulse.classList.remove("active");
            globalPulse.style.background = "var(--neon-green)";
            globalStatusTxt.textContent = "DONE";
        } else if (state === "error") {
            globalPulse.classList.remove("active");
            globalPulse.style.background = "var(--neon-red)";
            globalStatusTxt.textContent = "ERROR";
        } else {
            globalPulse.classList.remove("active");
            globalPulse.style.background = "";
            globalStatusTxt.textContent = "IDLE";
        }
    }

    function updateJobBadge(status) {
        const s = (status || "pending").toLowerCase();
        jobStatusBadge.textContent = s.toUpperCase();
        jobStatusBadge.className = `status-chip chip--${s}`;
    }

    function getModule(s) {
        s = (s || "").toLowerCase();
        if (s.includes("ingest") || s.includes("repo.ingest") || s === "m1")
            return { num:"m1", cardId:"card-ingest", name:"Code Ingestion" };
        if (s.includes("detect") || s.includes("rule.scan") || s === "m2")
            return { num:"m2", cardId:"card-detect", name:"Pattern Detection" };
        if (s.includes("reason") || s.includes("patch") || s === "m3")
            return { num:"m3", cardId:"card-reason", name:"Review & Patch Loop" };
        if (s.includes("exploit") || s.includes("verify") || s === "m4")
            return { num:"m4", cardId:"card-verify", name:"Exploit Verification" };
        if (s.includes("report") || s.includes("render") || s === "m5")
            return { num:"m5", cardId:"card-report", name:"Report Generator" };
        return null;
    }

    function setStageRunning(stage) {
        const m = getModule(stage);
        if (!m) return;
        const card  = document.getElementById(m.cardId);
        const badge = document.getElementById(`${m.num}-badge`);
        const note  = document.getElementById(`${m.num}-note`);
        if (card) card.classList.add("active-stage");
        setStep(m.num, "run", "active");
        setStep(m.num, "obs", "");
        setStep(m.num, "dec", "");
        if (badge && badge.textContent === "PENDING") {
            badge.textContent = "RUNNING";
            badge.className   = "agent-badge badge-running";
        }
        if (note) note.textContent = `Executing ${m.name}…`;
    }

    function updateComponentState(agent, decision, reason) {
        const m = getModule(agent);
        if (!m) return;
        const card  = document.getElementById(m.cardId);
        const badge = document.getElementById(`${m.num}-badge`);
        const note  = document.getElementById(`${m.num}-note`);
        if (card) {
            card.classList.remove("active-stage");
            card.classList.add("done-stage");
        }
        setStep(m.num, "run", "done");
        setStep(m.num, "obs", "done");
        setStep(m.num, "dec", "active");
        if (badge) {
            badge.textContent = decision || "COMPLETED";
            const isErr = ["ERROR","FAILED","FETCH_FAILED"].includes((decision||"").toUpperCase());
            badge.className = "agent-badge " + (isErr ? "badge-failed" : "badge-completed");
        }
        if (note) note.textContent = reason || "Stage processed.";
    }

    function markStageDone(stage) {
        const m = getModule(stage);
        if (!m) return;
        setStep(m.num, "dec", "done");
    }

    function setStep(num, step, cls) {
        const el = document.getElementById(`${num}-${step}`);
        if (!el) return;
        el.className = "astep" + (cls ? " " + cls : "");
    }

    function updateStats(summary) {
        if (!summary) return;
        if (statConfirmed && summary.confirmed_count !== undefined) {
            statConfirmed.textContent = summary.confirmed_count;
        }
        if (statEscalated && summary.escalated_count !== undefined) {
            statEscalated.textContent = summary.escalated_count;
        }
        if (statDuration && summary.duration_seconds !== undefined) {
            statDuration.textContent = `${Number(summary.duration_seconds).toFixed(1)}s`;
        }
    }

    function getSevClass(sev) {
        switch ((sev || "").toUpperCase()) {
            case "CRITICAL": return "badge-critical";
            case "HIGH":     return "badge-high";
            case "MEDIUM":   return "badge-medium";
            case "LOW":
            case "INFO":     return "badge-low";
            default:         return "badge-pending";
        }
    }

    function esc(str) {
        return (str == null ? "" : String(str))
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
