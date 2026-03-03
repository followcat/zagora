(function () {
  const $ = (id) => document.getElementById(id);

  const el = {
    server: $("server"),
    token: $("token"),
    sshUser: $("sshUser"),
    hostFilter: $("hostFilter"),
    newName: $("newName"),
    newHost: $("newHost"),
    saveBtn: $("saveBtn"),
    healthBtn: $("healthBtn"),
    createBtn: $("createBtn"),
    openViewBtn: $("openViewBtn"),
    closeOpenViewBtn: $("closeOpenViewBtn"),
    openView: $("openView"),
    sessions: $("sessions"),
    status: $("status"),
    count: $("count"),
    tpl: $("sessionTemplate"),
  };

  const KEY = "zagora_web_cfg_v1";
  let connected = false;
  let allSessions = [];

  function normalizeServer(raw) {
    const v = (raw || "").trim();
    if (!v) return "";
    if (v.startsWith("/")) return v.replace(/\/+$/, "");
    if (v.startsWith("http://") || v.startsWith("https://")) {
      return v.replace(/\/+$/, "");
    }
    return `http://${v}`.replace(/\/+$/, "");
  }

  function setStatus(text, type = "ok") {
    el.status.textContent = text;
    el.status.className = `status ${type}`;
  }

  function getCfg() {
    return {
      server: normalizeServer(el.server.value),
      token: el.token.value.trim(),
      sshUser: el.sshUser.value.trim(),
    };
  }

  function setConnected(v) {
    connected = Boolean(v);
    el.openViewBtn.disabled = !connected;
    if (!connected) {
      hideOpenView();
      allSessions = [];
      renderSessions([]);
    }
  }

  function showOpenView() {
    el.openView.classList.remove("hidden");
  }

  function hideOpenView() {
    el.openView.classList.add("hidden");
  }

  function saveCfg() {
    const cfg = {
      server: el.server.value.trim(),
      token: el.token.value.trim(),
      sshUser: el.sshUser.value.trim(),
      hostFilter: el.hostFilter.value.trim(),
    };
    localStorage.setItem(KEY, JSON.stringify(cfg));
    setStatus("Saved local config", "ok");
  }

  function loadCfg() {
    try {
      const cfg = JSON.parse(localStorage.getItem(KEY) || "{}");
      el.server.value = cfg.server || "";
      el.token.value = cfg.token || "";
      el.sshUser.value = cfg.sshUser || "";
      el.hostFilter.value = cfg.hostFilter || "";
    } catch (_) {
      // ignore bad localStorage payload
    }
  }

  async function api(path, init = {}) {
    const cfg = getCfg();
    if (!cfg.server) {
      throw new Error("server is required");
    }
    const url = `${cfg.server}${path}`;
    const headers = {};
    if (cfg.token) headers.Authorization = `Bearer ${cfg.token}`;
    if (init.body !== undefined && init.body !== null) {
      headers["Content-Type"] = "application/json";
    }
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 8000);
    let resp;
    try {
      resp = await fetch(url, {
        ...init,
        headers: { ...headers, ...(init.headers || {}) },
        signal: controller.signal,
      });
    } catch (e) {
      if (e && e.name === "AbortError") {
        throw new Error("request timeout (8s)");
      }
      throw e;
    } finally {
      window.clearTimeout(timeout);
    }
    const text = await resp.text();
    let data;
    try {
      data = text ? JSON.parse(text) : {};
    } catch (_) {
      data = { raw: text };
    }
    if (!resp.ok) {
      throw new Error(data.error || `${resp.status} ${resp.statusText}`);
    }
    return data;
  }

  function statusClass(status) {
    if (status === "running") return "status-running";
    if (status === "missing" || status === "unreachable") return `status-${status}`;
    return "";
  }

  function renderSessions(sessions) {
    el.sessions.innerHTML = "";
    el.count.textContent = String(sessions.length);
    if (!sessions.length) {
      el.sessions.innerHTML = '<div class="session-card"><div class="meta">No sessions</div></div>';
      return;
    }

    sessions.forEach((s) => {
      const node = el.tpl.content.firstElementChild.cloneNode(true);
      node.querySelector(".name").textContent = `${s.name} @ ${s.host}`;
      const sb = node.querySelector(".status-badge");
      sb.textContent = s.status || "unknown";
      const cls = statusClass(s.status || "");
      if (cls) sb.classList.add(cls);
      node.querySelector(".meta").textContent = `host_reachable: ${
        s.host_reachable === null || s.host_reachable === undefined ? "?" : s.host_reachable ? "up" : "down"
      }  ·  last_seen: ${s.last_seen || "-"}`;

      node.querySelector(".open-ssh").addEventListener("click", () => openSsh(s.host));
      node.querySelector(".remove").addEventListener("click", async () => {
        const ok = window.confirm(`Kill session ${s.name}@${s.host} ?`);
        if (!ok) return;
        try {
          await api(`/sessions/${encodeURIComponent(s.name)}?host=${encodeURIComponent(s.host)}`, {
            method: "DELETE",
          });
          setStatus(`Killed ${s.name}@${s.host}`, "ok");
          await loadSessions();
        } catch (e) {
          setStatus(`Kill failed: ${e.message}`, "err");
        }
      });

      el.sessions.appendChild(node);
    });
  }

  function applyFilter() {
    const q = el.hostFilter.value.trim().toLowerCase();
    if (!q) {
      renderSessions(allSessions);
      return;
    }
    const out = allSessions.filter((s) => {
      const fields = [s.name, s.host, s.status, s.last_seen]
        .map((x) => String(x || "").toLowerCase());
      return fields.some((x) => x.includes(q));
    });
    renderSessions(out);
  }

  function openSsh(host) {
    const cfg = getCfg();
    const target = cfg.sshUser ? `${cfg.sshUser}@${host}` : host;
    const uri = `ssh://${target}`;
    window.location.href = uri;
    const cmd = `ssh ${target}`;
    navigator.clipboard?.writeText(cmd).catch(() => {});
    setStatus(`Opened SSH link (${uri}). Copied fallback command.`, "ok");
  }

  async function loadSessions() {
    if (!connected) {
      setStatus("please connect first", "warn");
      return;
    }
    try {
      setStatus("ls ...", "warn");
      const sessions = await api("/sessions");
      allSessions = Array.isArray(sessions) ? sessions : [];
      applyFilter();
      setStatus(`ls ok: ${allSessions.length} sessions`, "ok");
    } catch (e) {
      setStatus(`Load failed: ${e.message}`, "err");
    }
  }

  async function createRecord() {
    if (!connected) {
      setStatus("please connect first", "warn");
      return;
    }
    const name = el.newName.value.trim();
    const host = el.newHost.value.trim();
    if (!name || !host) {
      setStatus("open requires name and host", "warn");
      return;
    }
    try {
      await api("/sessions", {
        method: "POST",
        body: JSON.stringify({ name, host, status: "running" }),
      });
      setStatus(`open ok: ${name}@${host}`, "ok");
      hideOpenView();
      el.newName.value = "";
      el.newHost.value = "";
      await loadSessions();
    } catch (e) {
      setStatus(`Create failed: ${e.message}`, "err");
    }
  }

  async function checkHealth() {
    try {
      const data = await api("/health");
      setConnected(true);
      setStatus(`connect ok: ${data.status || "ok"}`, "ok");
      await loadSessions();
    } catch (e) {
      setConnected(false);
      setStatus(`connect failed: ${e.message}`, "err");
    }
  }

  el.saveBtn.addEventListener("click", saveCfg);
  el.healthBtn.addEventListener("click", checkHealth);
  el.createBtn.addEventListener("click", createRecord);
  el.openViewBtn.addEventListener("click", showOpenView);
  el.closeOpenViewBtn.addEventListener("click", hideOpenView);
  el.hostFilter.addEventListener("input", applyFilter);

  loadCfg();
  setConnected(false);
  hideOpenView();
  if (el.server.value.trim()) {
    setStatus("auto connect ...", "warn");
    checkHealth();
  } else {
    setStatus("ready: fill server and click Connect");
  }
})();
