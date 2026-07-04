(function () {
  let controller = null;
  let scanData = { subdomains: [], admin: [], mx: [], summary: {} };

  const $ = (id) => document.getElementById(id);

  function resetCounters() {
    ["statSubs", "statAdmins", "statExposed", "statBypasses"].forEach(id => $(id).textContent = "0");
  }

  function bump(id) {
    const el = $(id);
    el.textContent = parseInt(el.textContent, 10) + 1;
  }

  function setStep(name, state) {
    const el = $("step-" + name);
    el.classList.remove("active", "done");
    if (state) el.classList.add(state);
  }

  function logRow(html, cls) {
    const feed = $("logFeed");
    if (feed.querySelector(".log-empty")) feed.innerHTML = "";
    const row = document.createElement("div");
    row.className = "log-row" + (cls ? " " + cls : "");
    row.innerHTML = html;
    feed.appendChild(row);
    feed.scrollTop = feed.scrollHeight;
  }

  function badge(text, kind) {
    return `<span class="badge badge-${kind}">${text}</span>`;
  }

  function renderSubRow(s) {
    let cls = "success";
    let tags = "";
    if (s.priv) { cls = "danger"; tags += badge("private ip", "danger"); }
    if (s.exposed && !s.cf) { cls = "warning"; tags += badge("cf bypass", "warning"); }
    if (s.cf) tags += badge("cloudflare", "neutral");
    if (!s.cf && !s.priv && !(s.exposed && !s.cf)) tags += badge("public", "success");

    logRow(`
      <span class="log-sub">${s.sub}</span>
      <span class="log-ip">${s.ip}</span>
      <span class="log-meta">${tags}</span>
    `, cls);
  }

  function renderAdminRow(a) {
    const kind = a.status === 200 ? "success" : a.status === 403 ? "danger" : "warning";
    logRow(`
      <span class="log-sub">${a.url}</span>
      <span class="log-ip">${a.server}</span>
      <span class="log-meta">${badge(a.status, kind)}</span>
    `, kind);
  }

  function renderMxRow(r) {
    logRow(`<span class="log-sub" style="color:var(--text-dim)">${r}</span>`, "");
  }

  function handleMsg(msg) {
    switch (msg.type) {
      case "phase":
        if (msg.phase === "subdomains") setStep("sub", "active");
        if (msg.phase === "mx") { setStep("sub", "done"); setStep("mx", "active"); }
        if (msg.phase === "admin") { setStep("mx", "done"); setStep("admin", "active"); }
        break;

      case "subdomain": {
        const s = msg.data;
        scanData.subdomains.push(s);
        renderSubRow(s);
        bump("statSubs");
        if (s.priv || (s.exposed && !s.cf)) bump("statExposed");
        if (s.exposed && !s.cf) bump("statBypasses");
        break;
      }

      case "mx":
        scanData.mx = msg.records;
        msg.records.forEach(renderMxRow);
        break;

      case "admin": {
        const a = msg.data;
        scanData.admin.push(a);
        renderAdminRow(a);
        bump("statAdmins");
        break;
      }

      case "done":
        scanData.summary = msg.summary;
        setStep("admin", "done");
        setStep("mx", "done");
        setStep("sub", "done");
        $("scanBtn").disabled = false;
        $("stopBtn").style.display = "none";
        $("exportBtn").style.display = "inline-flex";
        break;
    }
  }

  async function runScan() {
    const domain = $("domainInput").value.trim();
    if (!domain) { $("domainInput").focus(); return; }

    scanData = { subdomains: [], admin: [], mx: [], summary: {} };
    $("logFeed").innerHTML = "";
    resetCounters();
    ["sub", "mx", "admin"].forEach(s => setStep(s, null));

    $("statsBar").style.display = "grid";
    $("resultsCard").style.display = "block";
    $("scanBtn").disabled = true;
    $("stopBtn").style.display = "inline-flex";
    $("exportBtn").style.display = "none";

    controller = new AbortController();

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, admin: $("optAdmin").checked }),
        signal: controller.signal,
      });

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop();
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try { handleMsg(JSON.parse(line.slice(6))); } catch (e) {}
        }
      }
    } catch (e) {
      if (e.name !== "AbortError") {
        logRow(`<span class="log-sub" style="color:var(--danger)">Scan failed: ${e.message}</span>`, "danger");
      }
    } finally {
      $("scanBtn").disabled = false;
      $("stopBtn").style.display = "none";
    }
  }

  function stopScan() {
    if (controller) controller.abort();
    $("scanBtn").disabled = false;
    $("stopBtn").style.display = "none";
  }

  function exportResults() {
    const blob = new Blob([JSON.stringify(scanData, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `recon_${$("domainInput").value || "scan"}_${Date.now()}.json`;
    a.click();
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("scanBtn").addEventListener("click", runScan);
    $("stopBtn").addEventListener("click", stopScan);
    $("exportBtn").addEventListener("click", exportResults);
    $("domainInput").addEventListener("keydown", (e) => { if (e.key === "Enter") runScan(); });
  });
})();
