// ── Clock ─────────────────────────────────────────────────────────────────
function updateClock() {
    document.getElementById("clock").textContent =
        new Date().toLocaleTimeString("en-GB", {hour12: false});
}
setInterval(updateClock, 1000);
updateClock();

// ── Helpers ───────────────────────────────────────────────────────────────
function fmt(v) { return (v && v !== "unknown") ? v : "—"; }
function fmtTime(ts) { return ts ? new Date(ts * 1000).toLocaleTimeString() : "—"; }

function scoreToColor(s) {
    if (s > 70)  return "#00e676";
    if (s >= 40) return "#ffb300";
    return "#ff1744";
}

function decisionBadgeClass(d) {
    return {allow:"badge-allow", sandbox:"badge-sandbox", block:"badge-block",
            analysing:"badge-analysing", scanning:"badge-analysing",
            forwarding:"badge-analysing", done:"badge-idle"}[(d||"").toLowerCase()] || "badge-idle";
}

function decisionBadge(d) {
    return `<span class="badge ${decisionBadgeClass(d)}">${(d||"idle").toUpperCase()}</span>`;
}

function riskSpan(r) {
    const cls = {LOW:"risk-LOW", MEDIUM:"risk-MEDIUM", HIGH:"risk-HIGH"};
    return `<span class="${cls[r]||''}">${r||"—"}</span>`;
}

// ── SVG Gauge ─────────────────────────────────────────────────────────────
const ARC_LEN = 251.2;

function setGauge(score, reasons, status) {
    const arc   = document.getElementById("gaugeArc");
    const txt   = document.getElementById("gaugeScore");
    const label = document.getElementById("gaugeLabel");

    if (score === null || score === undefined) {
        arc.style.strokeDashoffset = ARC_LEN;
        arc.style.stroke = "#00d4ff";
        txt.textContent  = "--";
        txt.style.fill   = "#fff";
        const analysing = status && ["analysing","scanning","forwarding"].includes(status);
        label.textContent = analysing ? "ANALYSING..." : "NO DEVICE";
        label.style.color = analysing ? "#ffb300" : "var(--muted)";
        renderReasons([]);
        return;
    }

    const color  = scoreToColor(score);
    const offset = ARC_LEN - (score / 100) * ARC_LEN;

    arc.style.transition = "stroke-dashoffset 1s ease, stroke 0.5s";
    arc.style.strokeDashoffset = offset;
    arc.style.stroke = color;
    txt.textContent  = score;
    txt.style.fill   = color;

    if (score > 70)       { label.textContent = "TRUSTED";    label.style.color = "#00e676"; }
    else if (score >= 40) { label.textContent = "RESTRICTED"; label.style.color = "#ffb300"; }
    else                  { label.textContent = "BLOCKED";    label.style.color = "#ff1744"; }

    renderReasons(reasons || []);
}

function renderReasons(reasons) {
    const el = document.getElementById("reasonsList");
    if (!reasons.length) {
        el.innerHTML = `<div class="reason-empty">Connect a device to see breakdown</div>`;
        return;
    }
    el.innerHTML = reasons.map(r => `
      <div class="reason-row ${r.positive ? 'pos' : 'neg'}">
        <span class="reason-label">${r.label}</span>
        <span class="reason-pts ${r.positive ? 'pos' : 'neg'}">${r.points > 0 ? '+' : ''}${r.points}</span>
      </div>`).join("");
}

// ── Flow nodes ────────────────────────────────────────────────────────────
function setFlow(status, decision) {
    const usb     = document.getElementById("flowUSB");
    const sandbox = document.getElementById("flowSandbox");
    const host    = document.getElementById("flowHost");
    const flowSt  = document.getElementById("flowStatus");
    if (!usb) return;

    [usb, sandbox, host].forEach(n => n.className = "flow-node");

    const s = status || decision || "idle";
    if (s === "analysing" || s === "scanning") {
        usb.classList.add("active"); sandbox.classList.add("active");
        flowSt.textContent = "🔬 Analysing in sandbox...";
    } else if (s === "forwarding") {
        usb.classList.add("done-ok"); sandbox.classList.add("done-ok"); host.classList.add("active");
        flowSt.textContent = "📤 Forwarding clean files to host...";
    } else if (s === "allow" || s === "done") {
        [usb, sandbox, host].forEach(n => n.classList.add("done-ok"));
        flowSt.textContent = "✅ Clean files forwarded to host";
    } else if (s === "sandbox") {
        usb.classList.add("done-ok"); sandbox.classList.add("active");
        flowSt.textContent = "⚠️ Device sandboxed — restricted access";
    } else if (s === "block") {
        usb.classList.add("done-bad");
        flowSt.textContent = "🚫 Device blocked — access denied";
    } else {
        flowSt.textContent = "Monitoring...";
    }
}

// ── Render connected device cards ─────────────────────────────────────────
function renderConnected(devices) {
    const el = document.getElementById("deviceContent");

    if (!devices || devices.length === 0) {
        el.innerHTML = `
          <div class="idle-wrap">
            <div class="idle-hex">
              <svg width="60" height="60" viewBox="0 0 60 60"><polygon points="30,4 56,18 56,42 30,56 4,42 4,18" fill="none" stroke="rgba(0,212,255,0.2)" stroke-width="1.5"/></svg>
              <span class="idle-q">?</span>
            </div>
            <p class="idle-txt">Waiting for peripheral...</p>
            <p class="idle-sub">Connect a USB device to begin analysis</p>
          </div>`;
        setGauge(null, []);
        setFlow("idle", null);
        document.getElementById("decisionBadge").className = "badge badge-idle";
        document.getElementById("decisionBadge").textContent = "IDLE";
        return;
    }

    // Render each connected device as a card
    el.innerHTML = devices.map(d => {
        const status = d.status || "analysing";
        const score  = typeof d.trust_score === "number" ? d.trust_score : null;
        const color  = score !== null ? scoreToColor(score) : "var(--muted)";

        let statusBar = "";
        if (status === "analysing")  statusBar = `<div class="device-status-bar">🔍 Enumerating &amp; classifying...</div>`;
        else if (status === "scanning")   statusBar = `<div class="device-status-bar">🔬 Running sandbox scan...</div>`;
        else if (status === "forwarding") statusBar = `<div class="device-status-bar">📤 Forwarding clean files to host...</div>`;

        return `
        <div class="device-card" id="card-${CSS.escape(d.device_node)}">
          <div class="device-wrap">
            <div class="device-top">
              <span class="device-name">${fmt(d.manufacturer)} ${fmt(d.product)}</span>
              ${decisionBadge(status === "done" ? d.decision : status)}
            </div>
            <div class="device-grid">
              <div class="dfield"><span class="dfield-label">Vendor ID</span><span class="dfield-value">${fmt(d.vendor_id)}</span></div>
              <div class="dfield"><span class="dfield-label">Product ID</span><span class="dfield-value">${fmt(d.product_id)}</span></div>
              <div class="dfield"><span class="dfield-label">Manufacturer</span><span class="dfield-value">${fmt(d.manufacturer)}</span></div>
              <div class="dfield"><span class="dfield-label">Device Name</span><span class="dfield-value">${fmt(d.product)}</span></div>
              <div class="dfield"><span class="dfield-label">Device Type</span><span class="dfield-value">${fmt(d.device_class)}</span></div>
              <div class="dfield"><span class="dfield-label">Device Node</span><span class="dfield-value">${fmt(d.device_node)}</span></div>
              <div class="dfield"><span class="dfield-label">Serial Number</span><span class="dfield-value" style="font-size:0.68rem">${fmt(d.serial_number)}</span></div>
              <div class="dfield"><span class="dfield-label">Risk Level</span><span class="dfield-value">${riskSpan(d.risk_level)}</span></div>
            </div>
            ${score !== null ? `
            <div class="inline-score">
              <div class="inline-bar-wrap"><div class="inline-bar" style="width:${score}%;background:${color}"></div></div>
              <span class="inline-score-txt" style="color:${color}">Trust Score: <b>${score}</b>/100</span>
            </div>` : ""}
            ${statusBar}
          </div>
        </div>`;
    }).join('<div class="device-divider"></div>');

    // Update gauge with the most recently active device
    const active = [...devices].reverse().find(d =>
        d.trust_score !== undefined && d.trust_score !== null
    ) || devices[devices.length - 1];

    if (active) {
        const score = (active.trust_score !== undefined && active.trust_score !== null)
            ? active.trust_score : null;
        setGauge(score, active.score_reasons || [], active.status);
        setFlow(active.status, active.decision);
        const db = document.getElementById("decisionBadge");
        const disp = (active.status === "done" && active.decision) ? active.decision : active.status;
        db.className = "badge " + decisionBadgeClass(disp);
        db.textContent = (disp || "idle").toUpperCase();
    }
}

// ── Device History ────────────────────────────────────────────────────────
async function loadHistory() {
    try {
        const res  = await fetch("/devices");
        const data = await res.json();
        const tbody = document.getElementById("historyBody");
        if (!data.devices?.length) {
            tbody.innerHTML = `<tr><td colspan="10" class="empty-row">No devices recorded yet</td></tr>`;
            return;
        }
        tbody.innerHTML = data.devices.map(d => {
            const score = d.trust_score;
            const color = typeof score === "number" ? scoreToColor(score) : "var(--muted)";
            return `<tr>
              <td>${fmtTime(d.timestamp)}</td>
              <td>${fmt(d.manufacturer)}</td>
              <td>${fmt(d.product)}</td>
              <td>${fmt(d.vendor_id)}</td>
              <td>${fmt(d.product_id)}</td>
              <td style="font-size:0.65rem;max-width:100px;overflow:hidden;text-overflow:ellipsis">${fmt(d.serial_number)}</td>
              <td>${fmt(d.device_class)}</td>
              <td style="color:${color};font-weight:700">${score ?? "—"}</td>
              <td>${riskSpan(d.risk_level)}</td>
              <td>${decisionBadge(d.decision)}</td>
            </tr>`;
        }).join("");
    } catch(e) { console.error("History error", e); }
}

// ── Poll ──────────────────────────────────────────────────────────────────
async function poll() {
    try {
        const res  = await fetch("/current_device");
        const data = await res.json();
        renderConnected(data.devices || []);
    } catch(e) { console.error("Poll error", e); }
}

setInterval(() => { poll(); loadHistory(); }, 2000);
poll();
loadHistory();
