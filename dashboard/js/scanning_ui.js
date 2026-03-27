// ── Scan step → UI state map ──────────────────────────────────────────────────
//
// scan_step values emitted by backend (in order):
//   enumerated → classifying → classified → behaviour_check → behaviour_done
//   → mounting → extracting → clamav → yara → scoring → deciding → forwarding → done
//
// Scan rows:
//   scanBehaviour  (Behaviour Analysis)
//   scanSandbox    (Sandbox Inspection)
//   scanClamav     (ClamAV Scan)
//   scanYara       (YARA Analysis)

const STEP_ORDER = [
    "enumerated","classifying","classified",
    "behaviour_check","behaviour_done",
    "mounting","extracting",
    "clamav","yara",
    "scoring","deciding","forwarding","done"
];

function stepIndex(s) {
    const i = STEP_ORDER.indexOf(s);
    return i === -1 ? 0 : i;
}

function setScanRow(id, resultId, state, resultText) {
    const row = document.getElementById(id);
    const res = document.getElementById(resultId);
    if (!row || !res) return;
    row.className = "scan-row " + state;
    res.textContent = resultText;
    row.querySelector(".scan-icon").textContent =
        state === "done-ok" ? "✅" : state === "done-bad" ? "❌" : state === "running" ? "⟳" : "○";
}

function setProgress(pct) {
    const fill = document.getElementById("progressFill");
    const txt  = document.getElementById("progressPct");
    if (fill) { fill.style.transition = "width 0.4s ease"; fill.style.width = pct + "%"; }
    if (txt)  txt.textContent = pct + "%";
}

function resetScans() {
    ["scanClamav","scanYara","scanSandbox","scanBehaviour"].forEach(id => {
        const row = document.getElementById(id);
        if (row) row.className = "scan-row pending";
        const icon = row?.querySelector(".scan-icon");
        if (icon) icon.textContent = "○";
    });
    ["clamavResult","yaraResult","sandboxResult","behaviourResult"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = "Waiting";
    });
    setProgress(0);
}

// ── Main scan UI updater — driven by /scan_status ─────────────────────────────
async function updateScanUI() {
    try {
        const res  = await fetch("/scan_status");
        const d    = await res.json();
        const step = d.scan_step || "idle";
        const si   = stepIndex(step);

        if (step === "idle" || d.status === "idle") { resetScans(); return; }

        // ── Behaviour Analysis row ────────────────────────────────────────────
        if (si < stepIndex("behaviour_check")) {
            setScanRow("scanBehaviour", "behaviourResult", "pending", "Waiting");
        } else if (si === stepIndex("behaviour_check")) {
            setScanRow("scanBehaviour", "behaviourResult", "running", "Analysing...");
        } else {
            setScanRow("scanBehaviour", "behaviourResult",
                d.suspicious ? "done-bad" : "done-ok",
                d.suspicious ? "Suspicious" : "Normal");
        }

        // ── Sandbox Inspection row ────────────────────────────────────────────
        if (si < stepIndex("mounting")) {
            setScanRow("scanSandbox", "sandboxResult", "pending", "Waiting");
        } else if (si === stepIndex("mounting")) {
            setScanRow("scanSandbox", "sandboxResult", "running", "Mounting USB...");
        } else if (si === stepIndex("extracting")) {
            setScanRow("scanSandbox", "sandboxResult", "running", "Extracting files...");
        } else {
            setScanRow("scanSandbox", "sandboxResult", "done-ok",
                d.file_count ? `${d.file_count} files found` : "Secure");
        }

        // ── ClamAV row ────────────────────────────────────────────────────────
        if (si < stepIndex("clamav")) {
            setScanRow("scanClamav", "clamavResult", "pending", "Waiting");
        } else if (si === stepIndex("clamav")) {
            setScanRow("scanClamav", "clamavResult", "running", "Scanning...");
        } else {
            const infected = (d.file_results || []).filter(f => f.status === "infected").length;
            setScanRow("scanClamav", "clamavResult",
                infected > 0 ? "done-bad" : "done-ok",
                infected > 0 ? `${infected} infected` : "Clean");
        }

        // ── YARA row ──────────────────────────────────────────────────────────
        if (si < stepIndex("yara")) {
            setScanRow("scanYara", "yaraResult", "pending", "Waiting");
        } else if (si === stepIndex("yara")) {
            setScanRow("scanYara", "yaraResult", "running", "Analysing...");
        } else {
            const suspicious = (d.file_results || []).filter(f => f.status === "suspicious").length;
            setScanRow("scanYara", "yaraResult",
                suspicious > 0 ? "done-bad" : "done-ok",
                suspicious > 0 ? `${suspicious} patterns` : "No patterns");
        }

        // ── Progress bar ──────────────────────────────────────────────────────
        const pct = Math.round((si / (STEP_ORDER.length - 1)) * 100);
        setProgress(pct);

        // ── File panel (current device) ───────────────────────────────────────
        const files = d.file_results || [];
        const panel = document.getElementById("filePanel");
        const list  = document.getElementById("fileList");
        const count = document.getElementById("fileCount");
        if (files.length > 0 && panel) {
            panel.style.display = "block";
            count.textContent = files.length + " files";
            list.innerHTML = files.map(f => `
              <div class="file-row ${f.status}">
                <span class="file-name">${f.file}</span>
                <span class="file-tag ${f.status}">${f.status.toUpperCase()}</span>
              </div>`).join("");
        } else if (panel && si < stepIndex("clamav")) {
            panel.style.display = "none";
        }

    } catch(e) { console.error("Scan UI error", e); }
}

// ── Sandbox Proof ─────────────────────────────────────────────────────────────
async function loadSandboxProof() {
    try {
        const res  = await fetch("/sandbox_proof");
        const data = await res.json();

        const path = document.getElementById("proofPath");
        if (path) path.textContent = data.sandbox_path || "—";

        const mounts = document.getElementById("proofMounts");
        if (mounts) {
            if (data.active_mounts && data.active_mounts.length > 0) {
                mounts.textContent = data.active_mounts.length + " active — " + data.active_mounts[0];
                mounts.style.color = "var(--green)";
            } else {
                mounts.textContent = "None (no device scanning now)";
                mounts.style.color = "var(--muted)";
            }
        }

        const clamav = document.getElementById("proofClamav");
        if (clamav) {
            clamav.textContent = data.clamav_available ? "✅ " + data.clamav_path : "❌ Not installed";
            clamav.style.color = data.clamav_available ? "var(--green)" : "var(--red)";
        }

        const yara = document.getElementById("proofYara");
        if (yara) {
            yara.textContent = data.yara_available ? "✅ Installed" : "❌ Not installed";
            yara.style.color = data.yara_available ? "var(--green)" : "var(--red)";
        }
    } catch(e) { console.error("Sandbox proof error", e); }
}

// ── File Analysis Summary ─────────────────────────────────────────────────────
async function loadFileAnalysis() {
    try {
        const [scanRes, devRes] = await Promise.all([
            fetch("/scan_results"),
            fetch("/current_device")
        ]);
        const scanData = await scanRes.json();
        const devData  = await devRes.json();

        const reports = scanData.reports || [];
        const devices = devData.devices  || [];

        // Prefer current device file_results (live), fall back to DB scan reports
        let allFiles = [];
        const liveDevice = devices.find(x => (x.file_results || []).length > 0);
        if (liveDevice) {
            allFiles = liveDevice.file_results.map(f => ({
                file: f.file, status: f.status, device: liveDevice.device_node
            }));
        } else {
            allFiles = reports.flatMap(r => (r.file_results || []).map(f => ({
                file: f.file, status: f.status, device: r.device_node, ts: r.timestamp
            })));
        }

        const activeDevice = liveDevice || devices.find(d => d.trust_score != null);
        const trustScore   = activeDevice?.trust_score ?? null;
        const decision     = activeDevice?.decision    ?? null;

        const clean      = allFiles.filter(f => f.status === "clean").length;
        const infected   = allFiles.filter(f => f.status === "infected").length;
        const suspicious = allFiles.filter(f => f.status === "suspicious").length;
        const total      = allFiles.length;

        document.getElementById("faTotal").textContent      = total || "—";
        document.getElementById("faClean").textContent      = total ? clean      : "—";
        document.getElementById("faInfected").textContent   = total ? infected   : "—";
        document.getElementById("faSuspicious").textContent = total ? suspicious : "—";

        const scoreEl = document.getElementById("faTrustScore");
        if (scoreEl) {
            if (trustScore !== null) {
                const color = trustScore > 70 ? "var(--green)" : trustScore >= 40 ? "#ffb300" : "var(--red)";
                scoreEl.textContent = trustScore + "/100";
                scoreEl.style.color = color;
            } else {
                scoreEl.textContent = "—";
                scoreEl.style.color = "var(--muted)";
            }
        }

        const badge = document.getElementById("faScanBadge");
        if (total === 0 && trustScore === null) {
            badge.textContent = "No scans yet"; badge.className = "badge badge-idle";
        } else if (infected > 0) {
            badge.textContent = infected + " infected"; badge.className = "badge badge-block";
        } else if (suspicious > 0) {
            badge.textContent = suspicious + " suspicious"; badge.className = "badge badge-sandbox";
        } else if (decision === "allow" || trustScore > 70) {
            badge.textContent = "All clean"; badge.className = "badge badge-allow";
        } else if (decision === "sandbox") {
            badge.textContent = "Sandboxed"; badge.className = "badge badge-sandbox";
        } else if (decision === "block") {
            badge.textContent = "Blocked"; badge.className = "badge badge-block";
        } else {
            badge.textContent = total ? "All clean" : "No scans yet";
            badge.className   = total ? "badge badge-allow" : "badge badge-idle";
        }

        const list = document.getElementById("faFileList");
        if (allFiles.length === 0) {
            list.innerHTML = trustScore !== null
                ? `<div class="reason-empty">Score: ${trustScore}/100 — ${decision ? decision.toUpperCase() : "No files scanned"}</div>`
                : `<div class="reason-empty">No files analysed yet</div>`;
            return;
        }
        list.innerHTML = allFiles.slice(-30).reverse().map(f => `
          <div class="file-row ${f.status}">
            <span class="file-name" title="${f.device || ''}">&#128196; ${f.file}</span>
            <span class="file-tag ${f.status}">${f.status.toUpperCase()}</span>
          </div>`).join("");
    } catch(e) { console.error("File analysis error", e); }
}

setInterval(() => { updateScanUI(); loadSandboxProof(); loadFileAnalysis(); }, 1500);
updateScanUI();
loadSandboxProof();
loadFileAnalysis();
