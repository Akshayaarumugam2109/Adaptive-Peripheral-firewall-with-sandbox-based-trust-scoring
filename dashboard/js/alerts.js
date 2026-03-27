function alertClass(type) {
    const t = (type || "").toLowerCase();
    if (t.includes("block"))       return "al-block";
    if (t.includes("allow"))       return "al-allow";
    if (t.includes("sand"))        return "al-sandbox";
    if (t.includes("malware"))     return "al-malware";
    if (t.includes("suspicious"))  return "al-suspicious";
    return "";
}

function fmtTime(ts) {
    return ts ? new Date(ts * 1000).toLocaleTimeString() : "";
}

async function loadAlerts() {
    try {
        const res  = await fetch("/alerts");
        const data = await res.json();
        const list = document.getElementById("alertList");
        const countEl = document.getElementById("alertCount");
        const alerts = data.alerts || [];

        if (countEl) countEl.textContent = alerts.length;

        if (!alerts.length) {
            list.innerHTML = `<li class="empty-row">No alerts yet</li>`;
            return;
        }

        list.innerHTML = alerts.map(a => `
          <li class="${alertClass(a.alert_type)}">
            <span class="al-time">${fmtTime(a.timestamp)}</span>
            <div class="al-body">
              <div class="al-type">${a.alert_type || "ALERT"}</div>
              <div class="al-desc">${a.description || ""}${a.device_node ? " — " + a.device_node : ""}</div>
            </div>
          </li>`).join("");
    } catch(e) { console.error("Alerts error", e); }
}

setInterval(loadAlerts, 2000);
loadAlerts();
