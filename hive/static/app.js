/* WASP Hive dashboard.
 *
 * Every value shown here came from a VM's report or a Wazuh manager, so none
 * of it is trusted: the page is built with createElement and textContent only,
 * never innerHTML, and the server's CSP forbids inline script besides. A node
 * that reports "<img onerror=…>" as its hostname gets that text displayed.
 */
(function () {
  "use strict";

  var REFRESH_MS = 60000;
  var FW_SHORT = { cis8: "CIS", pci4: "PCI", hipaa: "HIPAA", soc2: "SOC 2", csf2: "CSF" };
  var STATUS_SYM = { pass: "✓", partial: "½", fail: "✗", unknown: "?", operator: "O", exempt: "E" };
  var app = document.getElementById("app");
  var timer = null;
  var state = { client: "", q: "", filter: "all", fw: "cis8", nodeFw: "cis8" };

  try {
    var saved = JSON.parse(localStorage.getItem("hive-view") || "{}");
    if (saved && typeof saved === "object") {
      ["client", "filter", "fw", "nodeFw"].forEach(function (k) { if (typeof saved[k] === "string") state[k] = saved[k]; });
    }
  } catch (e) { /* storage unavailable: defaults */ }
  function remember() {
    try { localStorage.setItem("hive-view", JSON.stringify({ client: state.client, filter: state.filter, fw: state.fw, nodeFw: state.nodeFw })); }
    catch (e) { /* ignore */ }
  }

  // ── DOM helpers ──────────────────────────────────────────────────────────
  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) return;
        if (k === "class") el.className = v;
        else if (k === "text") el.textContent = v;
        else if (k.slice(0, 2) === "on") el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? "" : String(v));
      });
    }
    for (var i = 2; i < arguments.length; i++) add(el, arguments[i]);
    return el;
  }
  function add(el, c) {
    if (c === null || c === undefined || c === false) return;
    if (Array.isArray(c)) { c.forEach(function (x) { add(el, x); }); return; }
    el.appendChild(typeof c === "object" ? c : document.createTextNode(String(c)));
  }
  function svg(tag, attrs) {
    var el = document.createElementNS("http://www.w3.org/2000/svg", tag);
    Object.keys(attrs || {}).forEach(function (k) { el.setAttribute(k, attrs[k]); });
    return el;
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function show(node) { clear(app); add(app, node); }

  // ── Formatting ───────────────────────────────────────────────────────────
  function ago(epoch, now) {
    if (!epoch) return "never";
    var s = Math.max(0, (now || Date.now() / 1000) - epoch);
    if (s < 90) return Math.round(s) + "s ago";
    if (s < 5400) return Math.round(s / 60) + " min ago";
    if (s < 172800) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " d ago";
  }
  function when(epoch) { return epoch ? new Date(epoch * 1000).toISOString().replace("T", " ").slice(0, 16) + " UTC" : "never"; }
  function untilText(epoch) {
    var s = epoch - Date.now() / 1000;
    return s <= 0 ? "closing" : Math.ceil(s / 60) + " min left";
  }
  function dur(sec) {
    sec = Number(sec) || 0;
    var d = Math.floor(sec / 86400), hr = Math.floor((sec % 86400) / 3600);
    return d ? d + "d " + hr + "h" : hr + "h " + Math.floor((sec % 3600) / 60) + "m";
  }
  function stateLabel(s) { return { ok: "healthy", warning: "warning", critical: "critical", stale: "stale", never: "never reported" }[s] || s; }
  function pill(cls, text) { return h("span", { class: "pill " + cls, text: text || cls }); }
  function okText(v, good, bad) { return v ? h("span", { class: "good", text: good || "yes" }) : h("span", { class: "bad", text: bad || "no" }); }
  function scoreClass(n) { return n === null || n === undefined ? "" : n >= 85 ? "hi" : n >= 60 ? "mid" : "lo"; }

  // ── API ──────────────────────────────────────────────────────────────────
  function api(path, opts) {
    opts = opts || {};
    return fetch(path, {
      method: opts.method || "GET",
      credentials: "same-origin",
      headers: opts.body ? { "Content-Type": "application/json" } : {},
      body: opts.body ? JSON.stringify(opts.body) : undefined
    }).then(function (r) {
      if (r.status === 401 && path !== "/api/v1/login") { loginView(); throw new Error("login"); }
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok) { var e = new Error(j.error || ("HTTP " + r.status)); e.status = r.status; throw e; }
        return j;
      });
    });
  }
  function fail(err) {
    if (err && err.message === "login") return;
    show(h("div", { class: "panel" }, h("p", { class: "error", text: "Could not load: " + (err && err.message || err) })));
  }

  // ── Chrome ───────────────────────────────────────────────────────────────
  function chrome(on, data) {
    document.getElementById("nav").hidden = !on;
    document.getElementById("topright").hidden = !on;
    if (!on) return;
    var route = location.hash.indexOf("#/compliance") === 0 ? "compliance" : "fleet";
    document.querySelectorAll("#nav a").forEach(function (a) { a.classList.toggle("on", a.getAttribute("data-nav") === route); });
    document.getElementById("refreshed").textContent = "updated " + new Date().toLocaleTimeString();
    if (data && data.wazuh) {
      var w = data.wazuh, chip = document.getElementById("wazuh-chip");
      chip.className = "chip";
      if (!w.configured) { chip.textContent = "Wazuh: not configured"; }
      else if (w.ok) { chip.textContent = "Wazuh: " + (w.matched || 0) + "/" + (w.agents || 0) + " agents" + (w.pinned ? "" : " (unpinned)"); chip.classList.add(w.pinned ? "ok" : "bad"); }
      else if (w.ok === false) { chip.textContent = "Wazuh: error"; chip.title = w.error || ""; chip.classList.add("bad"); }
      else { chip.textContent = "Wazuh: connecting"; }
    }
  }

  function schedule(fn) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(function () { if (!document.hidden) fn(); else schedule(fn); }, REFRESH_MS);
  }

  // ── Login ────────────────────────────────────────────────────────────────
  function loginView() {
    if (timer) clearTimeout(timer);
    chrome(false);
    var tpl = document.getElementById("login-tpl").content.cloneNode(true);
    show(tpl);
    var form = document.getElementById("login-form"), errEl = document.getElementById("login-error");
    form.elements.user.focus();
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      errEl.textContent = "";
      api("/api/v1/login", { method: "POST", body: {
        user: form.elements.user.value, password: form.elements.password.value, totp: form.elements.totp.value.trim() } })
        .then(function (j) { form.reset(); document.getElementById("who").textContent = j.user || ""; route(); })
        .catch(function (e) {
          errEl.textContent = e.status === 429 ? e.message : "Sign-in failed. Check the password and use a fresh code.";
          form.elements.totp.value = "";
        });
    });
  }

  // ── Fleet ────────────────────────────────────────────────────────────────
  function fleetView() {
    api("/api/v1/fleet").then(function (d) {
      chrome(true, d);
      var nodes = d.nodes || [];
      var clients = Array.from(new Set(nodes.map(function (n) { return n.client || ""; }))).sort();
      if (state.client && clients.indexOf(state.client) < 0) state.client = "";

      var count = { ok: 0, warning: 0, critical: 0, stale: 0, never: 0 }, vulnCH = 0, malC = 0, bans = 0;
      nodes.forEach(function (n) {
        count[n.state] = (count[n.state] || 0) + 1;
        if (n.vulns) vulnCH += (n.vulns.CRITICAL || 0) + (n.vulns.HIGH || 0);
        if (n.malware) malC += n.malware.CRITICAL || 0;
        if (n.crowdsec) bans += n.crowdsec.decisions || 0;
      });
      function kpi(v, label, cls) { return h("div", { class: "kpi " + (v === 0 && cls !== "ok" ? "zero" : cls || "") }, h("div", { class: "v", text: v }), h("div", { class: "l", text: label })); }

      var tilesEl = h("div", { class: "tiles" });
      var search = h("input", { type: "search", placeholder: "Filter by node, domain or client", value: state.q, "aria-label": "Filter nodes" });
      var clientSel = h("select", { "aria-label": "Client" }, h("option", { value: "", text: "All clients" }),
        clients.filter(Boolean).map(function (c) { return h("option", { value: c, text: c, selected: c === state.client }); }));
      var seg = h("div", { class: "seg", role: "group", "aria-label": "Show" });
      [["all", "All"], ["attention", "Needs attention"], ["ok", "Healthy"]].forEach(function (f) {
        add(seg, h("button", { type: "button", class: state.filter === f[0] ? "on" : "", text: f[1], onclick: function () {
          state.filter = f[0]; remember();
          seg.querySelectorAll("button").forEach(function (b) { b.classList.toggle("on", b === this); }, this);
          draw();
        } }));
      });
      search.addEventListener("input", function () { state.q = search.value; draw(); });
      clientSel.addEventListener("change", function () { state.client = clientSel.value; remember(); draw(); });

      function draw() {
        clear(tilesEl);
        var q = state.q.toLowerCase();
        var shown = nodes.filter(function (n) {
          if (state.client && (n.client || "") !== state.client) return false;
          if (state.filter === "attention" && n.state === "ok") return false;
          if (state.filter === "ok" && n.state !== "ok") return false;
          if (q && (n.node + " " + (n.client || "") + " " + (n.domain || "")).toLowerCase().indexOf(q) < 0) return false;
          return true;
        });
        var rank = { critical: 0, warning: 1, stale: 2, never: 3, ok: 4 };
        shown.sort(function (a, b) { return (rank[a.state] - rank[b.state]) || a.node.localeCompare(b.node); });
        if (!shown.length) add(tilesEl, h("p", { class: "empty", text: nodes.length ? "No node matches." : "No nodes enrolled yet. On this VM: hive-admin enroll <node>" }));
        shown.forEach(function (n) { add(tilesEl, tile(n, d.generated_at)); });
      }
      draw();

      show([
        h("div", { class: "kpis" },
          kpi(nodes.length, "Nodes", ""), kpi(count.ok, "Healthy", "ok"), kpi(count.warning, "Warning", "warning"),
          kpi(count.critical, "Critical", "critical"), kpi(count.stale + count.never, "Stale / silent", "stale"),
          kpi(vulnCH, "Critical + high vulns", "critical"), kpi(malC, "Malware critical", "critical"),
          kpi(bans, "Active bans", "")),
        h("div", { class: "toolbar" }, search, clientSel, seg),
        tilesEl
      ]);
      schedule(fleetView);
    }).catch(fail);
  }

  function tile(n, now) {
    var go = function () { location.hash = "#/node/" + encodeURIComponent(n.node); };
    var t = h("div", { class: "tile " + n.state, tabindex: "0", role: "link", "aria-label": n.node + ", " + stateLabel(n.state),
      onclick: go, onkeydown: function (e) { if (e.key === "Enter") go(); } });
    add(t, h("div", { class: "tile-head" },
      h("div", { class: "tile-name", title: n.node, text: n.node }),
      pill(n.state, stateLabel(n.state))));
    add(t, h("div", { class: "tile-sub muted" },
      (n.client ? n.client + " · " : "") + (n.state === "never" ? "never reported" :
        "WASP " + (n.release || "?") + " · WP " + ((n.versions && n.versions.wordpress) || "?") + " · " + ago(now - (n.age_minutes || 0) * 60, now))));
    if (n.state === "never") return t;
    var v = n.vulns || {}, m = n.malware || {}, cs = n.crowdsec || {};
    add(t, h("div", { class: "stats" },
      h("div", { class: "stat" }, h("div", { class: "l", text: "Vulns C/H/M" }),
        h("div", { class: "v" }, h("span", { class: v.CRITICAL ? "sev-c" : "muted", text: v.CRITICAL || 0 }), "/",
          h("span", { class: v.HIGH ? "sev-h" : "muted", text: v.HIGH || 0 }), "/",
          h("span", { class: v.MEDIUM ? "sev-m" : "muted", text: v.MEDIUM || 0 }),
          n.vuln_result === "incomplete" ? h("span", { class: "meh", title: "Last scan incomplete", text: " !" }) : null)),
      h("div", { class: "stat" }, h("div", { class: "l", text: "Malware" }),
        h("div", { class: "v" }, (m.CRITICAL || m.HIGH) ?
          h("span", { class: m.CRITICAL ? "sev-c" : "sev-h", text: (m.CRITICAL || 0) + "C " + (m.HIGH || 0) + "H" }) :
          h("span", { class: "good", text: "clean" }))),
      h("div", { class: "stat" }, h("div", { class: "l", text: "Integrity" }),
        h("div", { class: "v" }, h("span", { class: n.integrity === "pass" && n.checksums !== "fail" ? "good" : n.integrity === "fail" || n.checksums === "fail" ? "bad" : "muted",
          text: n.integrity === "fail" || n.checksums === "fail" ? "FAIL" : n.integrity === "pass" ? "pass" : n.integrity || "?" }))),
      h("div", { class: "stat" }, h("div", { class: "l", text: "Bans / 24h" }),
        h("div", { class: "v" }, h("span", { class: cs.lapi_ok === false ? "bad" : "", title: cs.lapi_ok === false ? "LAPI unreachable" : "",
          text: (cs.decisions || 0) + " / " + (cs.alerts_24h || 0) })))));
    var cb = h("div", { class: "cbars" });
    Object.keys(FW_SHORT).forEach(function (k) {
      var sc = n.compliance ? n.compliance[k] : null;
      if (sc === undefined) return;
      var bar = h("i", { class: scoreClass(sc) }); bar.style.width = (sc || 0) + "%";
      add(cb, [h("span", { class: "muted", text: FW_SHORT[k] }), h("div", { class: "cbar" }, bar), h("span", { class: "n", text: sc === null ? "–" : sc + "%" })]);
    });
    add(t, cb);
    return t;
  }

  // ── Node ─────────────────────────────────────────────────────────────────
  function nodeView(name) {
    api("/api/v1/node/" + encodeURIComponent(name)).then(function (d) {
      chrome(true, { wazuh: d.wazuh_status });
      var head = [h("a", { class: "back", href: "#/", text: "← Fleet" }),
        h("div", { class: "node-head" }, h("h1", { text: d.node }), pill(d.summary ? d.summary.state : "never", stateLabel(d.summary ? d.summary.state : "never")))];
      if (d.state === "never") {
        show([head, h("div", { class: "panel" }, h("p", { class: "muted", text: "Enrolled but never reported. On the VM: doas wasp-hive-report.sh status" }))]);
        return schedule(function () { nodeView(name); });
      }
      var r = d.report || {}, s = d.summary || {};
      head.push(h("div", { class: "meta muted" },
        [d.client, r.domain, r.hostname, "WASP " + (r.wasp_release || "?"), "from " + d.source_ip, "last report " + ago(d.received_at)]
          .filter(Boolean).join(" · ")));

      show([head, h("div", { class: "grid" },
        panel("Health", "span-4", healthPanel(r)),
        panel("Versions", "span-4", kv([["WordPress", (r.versions || {}).wordpress], ["PHP", (r.versions || {}).php], ["MariaDB", (r.versions || {}).mariadb], ["WASP", r.wasp_release]])),
        panel("Backups", "span-4", backupPanel(r.backups || {})),
        panel("Last 30 days", "span-12", sparks(d.history || [])),
        panel("Vulnerabilities", "span-8", vulnPanel(r.vulns || {})),
        panel("CrowdSec", "span-4", crowdsecPanel(r.crowdsec || {})),
        panel("Malware", "span-6", malwarePanel(r.malware || {})),
        panel("Integrity", "span-3", integrityPanel(r.integrity || {})),
        panel("Egress open now", "span-3", egressPanel((r.egress || {}).temporary || [])),
        panel("Wazuh", "span-12", wazuhPanel(d)),
        panel("Compliance evidence", "span-12", compliancePanel(d.compliance || {})),
        panel("Controls reported", "span-12", controlsPanel(r.controls || {}))
      )]);
      schedule(function () { nodeView(name); });
    }).catch(fail);
  }

  function panel(title, span, body) { return h("section", { class: "panel " + span }, h("h2", { text: title }), body); }
  function kv(rows) {
    var g = h("div", { class: "kv" });
    rows.forEach(function (r) { add(g, [h("div", { class: "k", text: r[0] }), h("div", { class: "v" }, r[1] === undefined || r[1] === null || r[1] === "" ? "–" : r[1])]); });
    return g;
  }
  function table(cols, rows, emptyText) {
    if (!rows.length) return h("p", { class: "empty", text: emptyText || "None." });
    return h("div", { class: "tbl-wrap" }, h("table", null,
      h("thead", null, h("tr", null, cols.map(function (c) { return h("th", { text: c }); }))),
      h("tbody", null, rows.map(function (r) { return h("tr", null, r.map(function (c) { return c instanceof Node ? h("td", null, c) : h("td", { class: "mono", text: c === undefined || c === null ? "" : c }); })); }))));
  }
  function sevSpan(sev) { return h("span", { class: { CRITICAL: "sev-c", HIGH: "sev-h", MEDIUM: "sev-m", SUSPICIOUS: "sev-m" }[sev] || "sev-l", text: sev }); }

  function healthPanel(r) {
    var hl = r.health || {}, rc = hl.check_rc;
    return kv([["Check", h("span", { class: rc === 0 ? "good" : rc === 1 ? "meh" : "bad", text: hl.check || "?" })],
      ["Disk used", (hl.disk_used_pct || 0) + "%"], ["Uptime", dur(hl.uptime_s)], ["Reported", when(r.sent_at)]]);
  }
  function backupPanel(b) {
    var now = Date.now() / 1000;
    function fresh(t) { return h("span", { class: t && now - t < 36 * 3600 ? "good" : "bad", text: ago(t) }); }
    return kv([["Local DB dump", fresh(b.local_at)],
      ["Off-VM", b.offsite_configured ? fresh(b.offsite_at) : h("span", { class: "meh", text: "not configured" })],
      ["Off-VM error", b.offsite_error ? h("span", { class: "bad", text: "last run failed" }) : "none"]]);
  }
  function vulnPanel(v) {
    var f = v.findings || [];
    var top = kv([["Last scan", h("span", { class: v.at && Date.now() / 1000 - v.at < 48 * 3600 ? "" : "bad", text: ago(v.at) })],
      ["Result", h("span", { class: v.result === "complete" ? "good" : "bad", text: v.result || "unknown" })],
      ["Sources", v.sources || "–"]]);
    return [top, h("div", { class: "spacer" }), table(["Severity", "Component", "Vulnerability", "CVE"],
      f.map(function (x) { return [sevSpan(x.severity), x.component, x.title, x.cve]; }), "No known vulnerability in installed versions.")];
  }
  function malwarePanel(m) {
    var f = m.findings || [];
    return [kv([["Last scan", ago(m.at)]]), table(["Severity", "Finding", "Detail"],
      f.map(function (x) { return [sevSpan(x.severity), x.finding, x.detail]; }), "No findings on the last live-site scan.")];
  }
  function integrityPanel(i) {
    var tCls = i.tooling === "pass" ? "good" : i.tooling === "fail" ? "bad" : "meh";
    return kv([["WASP tooling", h("span", { class: tCls, text: i.tooling || "?" })],
      ["Modified", i.tooling_modified || 0],
      ["Core/plugins", h("span", { class: i.checksums === "pass" ? "good" : i.checksums === "fail" ? "bad" : "meh", text: i.checksums || "?" })],
      ["Checked", ago(i.checksums_at)], ["Files changed", i.checksums_modified || 0]]);
  }
  function crowdsecPanel(c) {
    var top = kv([["Mode", c.mode === "upstream" ? "upstream (bans at the proxy)" : "local bouncer"],
      ["LAPI", okText(c.lapi_ok, "connected", "unreachable")],
      ["Bouncer", c.bouncer === "active" ? h("span", { class: "good", text: "active" }) : c.bouncer === "n/a" ? "n/a" : h("span", { class: "bad", text: c.bouncer || "?" })],
      ["Active bans", c.decisions || 0], ["Alerts 24h", c.alerts_24h || 0],
      ["AppSec (WAF)", appsecText(c.appsec)]]);
    var sc = c.top_scenarios || [];
    if (!sc.length) return top;
    var max = Math.max.apply(null, sc.map(function (x) { return x.count || 0; })) || 1;
    var bars = h("div", { class: "hbars" });
    sc.forEach(function (x) {
      var b = h("i"); b.style.width = (100 * (x.count || 0) / max) + "%";
      add(bars, [h("div", { class: "name", title: x.scenario, text: String(x.scenario).replace(/^crowdsecurity\//, "") }), h("div", { class: "hbar" }, b), h("div", { class: "mono", text: x.count })]);
    });
    return [top, h("h2", { class: "sub", text: "Top scenarios, 24h" }), bars];
  }
  function appsecText(a) {
    if (!a) return h("span", { class: "muted", text: "not reported" });
    if (!a.enabled) return h("span", { class: "muted", text: "off — logs only" });
    if (!a.listening) return h("span", { class: "bad", text: "ON but not listening — uninspected" });
    var t = "on · " + (a.blocked_24h || 0) + " blocked 24h · " + (a.mem_mb || 0) + " MB";
    if (a.watchdog_restarts_24h) t += " · " + a.watchdog_restarts_24h + " restart(s)";
    if (a.failure_action === "ban") t += " · fail-closed";
    return h("span", { class: a.watchdog_restarts_24h ? "meh" : "good", text: t });
  }
  function egressPanel(t) {
    if (!t.length) return h("p", { class: "good", text: "Nothing temporary. Only the permanent allowlist." });
    return table(["Domain", "Tag", "Closes"], t.map(function (x) { return [x.domain, x.tag, untilText(x.until)]; }));
  }
  function controlsPanel(c) {
    var labels = [["mfa_enforce", "MFA enforced"], ["admin_ip_restricted", "wp-admin IP-restricted"], ["login_slug", "Login slug moved"],
      ["egress_proxy", "Egress proxy"], ["restrict_egress", "VM egress restricted"], ["geoip", "GeoIP"], ["clamav", "ClamAV"],
      ["wordfence_feed", "Wordfence feed"], ["wpvulnerability", "WPVulnerability"], ["smtp_alerts", "Alert e-mail"], ["heartbeat", "Heartbeat"]];
    var g = h("div", { class: "kv" });
    var optional = { geoip: 1, clamav: 1 };   // off is a choice, not a gap
    labels.forEach(function (l) {
      add(g, [h("div", { class: "k", text: l[1] }), h("div", { class: "v" },
        optional[l[0]] && !c[l[0]] ? h("span", { class: "muted", text: "off (optional)" }) : okText(c[l[0]], "on", "off"))]);
    });
    add(g, [h("div", { class: "k", text: "Profile" }), h("div", { class: "v", text: c.deployment_profile || "?" }),
      h("div", { class: "k", text: "Release signature" }), h("div", { class: "v" }, h("span", { class: c.release_signature === "verified" ? "good" : "bad", text: c.release_signature || "?" }))]);
    return g;
  }

  function sparks(hist) {
    var wrap = h("div", { class: "sparks" });
    if (hist.length < 2) { add(wrap, h("p", { class: "empty", text: "Trends appear after a few hours of reports." })); return wrap; }
    [["vuln", "Known vulnerabilities"], ["malware", "Malware C+H"], ["decisions", "Active bans"], ["alerts", "CrowdSec alerts / 24h"], ["disk", "Disk used %"]]
      .forEach(function (k) {
        var pts = hist.map(function (p) { return [p.t, Number(p[k[0]]) || 0]; });
        var t0 = pts[0][0], t1 = pts[pts.length - 1][0] || t0 + 1, vmax = Math.max.apply(null, pts.map(function (p) { return p[1]; }));
        if (k[0] === "disk") vmax = 100; else vmax = Math.max(vmax, 1);
        var W = 300, H = 44;
        var coords = pts.map(function (p) { return ((p[0] - t0) / Math.max(1, t1 - t0) * W).toFixed(1) + "," + (H - 2 - p[1] / vmax * (H - 4)).toFixed(1); });
        var s = svg("svg", { viewBox: "0 0 " + W + " " + H, preserveAspectRatio: "none", role: "img", "aria-label": k[1] + " trend" });
        s.appendChild(svg("path", { d: "M0," + H + " L" + coords.join(" L") + " L" + W + "," + H + " Z" }));
        s.appendChild(svg("polyline", { points: coords.join(" ") }));
        add(wrap, h("div", { class: "spark" }, h("div", { class: "top-line" }, h("span", { text: k[1] }), h("b", { text: pts[pts.length - 1][1] + (k[0] === "disk" ? "%" : "") })), s));
      });
    return wrap;
  }

  function wazuhPanel(d) {
    var st = d.wazuh_status || {};
    if (!st.configured) return h("p", { class: "muted", text: "No Wazuh manager configured on this Hive. WASP's own file-integrity and malware checks are shown above; set WAZUH_URL in hive.conf to add the manager's view." });
    var w = d.wazuh;
    if (!w) return h("p", { class: "meh", text: "The manager has no agent named " + d.node + ". Install the Wazuh agent on the VM with this name to see it here." });
    var a = w.agent || {};
    var out = [kv([["Agent", a.id + " · " + (a.version || "?")],
      ["Status", h("span", { class: a.status === "active" ? "good" : "bad", text: a.status || "?" })],
      ["Last keep-alive", a.lastKeepAlive || "–"], ["Polled", ago(d.wazuh_at)],
      ["Manager link", st.pinned ? "certificate pinned" : h("span", { class: "bad", text: "NOT pinned (encrypted, unauthenticated)" })]])];
    var sca = w.sca || [];
    out.push(h("h2", { class: "sub", text: "Configuration assessment (SCA)" }));
    if (sca.length) {
      out.push(table(["Policy", "Pass", "Fail", "N/A", "Score", "Scanned"], sca.map(function (p) {
        return [p.name || p.policy_id, p.pass, h("span", { class: p.fail ? "bad" : "", text: p.fail }), p.invalid, (p.score === undefined ? "" : p.score + "%"), p.end_scan || ""];
      })));
    } else out.push(h("p", { class: "empty", text: w.sca_error ? "SCA unavailable: " + w.sca_error : "No SCA results." }));
    var fim = w.fim || [];
    out.push(h("h2", { class: "sub", text: "File integrity (most recent)" }));
    if (fim.length) {
      out.push(table(["File", "Changes", "Size", "Modified", "Seen"], fim.map(function (f) { return [f.file, f.changes, f.size, f.mtime, f.date]; })));
    } else out.push(h("p", { class: "empty", text: w.fim_error ? "FIM unavailable: " + w.fim_error : "No file-integrity events." }));
    return out;
  }

  function evidenceList(row) {
    var ul = h("ul", { class: "ev" });
    (row.evidence || []).forEach(function (e) {
      add(ul, h("li", null, h("span", { class: e.ok === true ? "ok" : e.ok === false ? "no" : "unk", text: e.ok === true ? "✓" : e.ok === false ? "✗" : "?" }),
        h("span", { text: e.title + " — " + e.observed })));
    });
    return ul;
  }

  function compliancePanel(ev) {
    var ids = Object.keys(ev);
    if (!ids.length) return h("p", { class: "empty", text: "No compliance data." });
    if (ids.indexOf(state.nodeFw) < 0) state.nodeFw = ids[0];
    var body = h("div");
    var tabs = h("div", { class: "tabs", role: "tablist" });
    ids.forEach(function (id) {
      add(tabs, h("button", { type: "button", role: "tab", class: id === state.nodeFw ? "on" : "", "aria-selected": id === state.nodeFw ? "true" : "false",
        onclick: function () { state.nodeFw = id; remember(); tabs.querySelectorAll("button").forEach(function (b) { b.classList.toggle("on", b === this); b.setAttribute("aria-selected", b === this); }, this); draw(); } },
        ev[id].name, h("span", { class: "score " + scoreClass(ev[id].score), text: ev[id].score === null ? "" : ev[id].score + "%" })));
    });
    function draw() {
      clear(body);
      var fw = ev[state.nodeFw], t = fw.tally;
      add(body, h("div", { class: "tally" }, ["pass", "partial", "fail", "unknown", "operator", "exempt"].map(function (k) { return pill(k, k + " " + (t[k] || 0)); })));
      add(body, table(["Control", "Status", "Evidence / reason"], fw.controls.map(function (c) {
        var detail = c.status === "operator" || c.status === "exempt" ? h("div", { class: "reason", text: c.reason || "" }) :
          h("div", null, evidenceList(c), c.note ? h("div", { class: "note", text: c.note }) : null);
        return [h("div", null, h("b", { class: "mono", text: c.id }), " ", c.title), pill(c.status), detail];
      })));
    }
    draw();
    return [tabs, body];
  }

  // ── Compliance matrix ────────────────────────────────────────────────────
  function complianceView() {
    api("/api/v1/frameworks").then(function (fws) {
      var list = fws.frameworks || [];
      if (!list.some(function (f) { return f.id === state.fw; })) state.fw = list.length ? list[0].id : "";
      return api("/api/v1/compliance/" + encodeURIComponent(state.fw)).then(function (d) {
        chrome(true, null);
        var tabs = h("div", { class: "tabs", role: "tablist" }, list.map(function (f) {
          return h("button", { type: "button", role: "tab", class: f.id === state.fw ? "on" : "", "aria-selected": f.id === state.fw ? "true" : "false",
            text: f.name, onclick: function () { state.fw = f.id; remember(); complianceView(); } });
        }));
        var fw = d.framework, nodes = (d.nodes || []).filter(function (n) { return !state.client || (n.client || "") === state.client; });
        var thead = h("tr", null, h("th", { text: "Control" }), nodes.map(function (n) {
          return h("th", { class: "node", title: (n.client ? n.client + " / " : "") + n.node },
            h("a", { href: "#/node/" + encodeURIComponent(n.node), text: n.node }));
        }));
        var scoreRow = h("tr", { class: "scope-row" }, h("td", null, h("b", { text: "Score" })), nodes.map(function (n) {
          return h("td", { class: "cell mono", text: n.score === null || n.score === undefined ? "–" : n.score });
        }));
        var rows = fw.controls.map(function (c, i) {
          var label = h("td", { class: "ctl" }, h("span", { class: "id", text: c.id }), c.title,
            c.note ? h("div", { class: "note", text: c.note }) : null);
          if (c.status === "operator" || c.status === "exempt") {
            return h("tr", null, label, h("td", { class: "span", colspan: String(Math.max(1, nodes.length)) }, pill(c.status), " ", c.reason || ""));
          }
          return h("tr", null, label, nodes.map(function (n) {
            var st = (n.statuses || [])[i] || "unknown";
            return h("td", { class: "cell " + st, title: n.node + ": " + st + "\n" + (c.checks || []).map(function (k) { return "• " + (d.checks[k] || k); }).join("\n"), text: STATUS_SYM[st] || "?" });
          }));
        });
        show([
          h("h1", { text: "Compliance" }),
          h("p", { class: "disclaimer", text: d.disclaimer }),
          tabs,
          fw.scope ? h("p", { class: "muted", text: "Scope: " + fw.scope }) : null,
          nodes.length ? h("div", { class: "panel tbl-wrap" }, h("table", { class: "matrix" }, h("thead", null, thead), h("tbody", null, scoreRow, rows))) :
            h("p", { class: "empty", text: "No nodes." }),
          h("div", { class: "legend" }, [["pass", "evidence present"], ["partial", "some evidence"], ["fail", "evidence says no"], ["unknown", "not reported (older WASP)"],
            ["operator", "MSP's process, not a VM's"], ["exempt", "does not apply to a WASP VM"]].map(function (l) {
            return h("span", null, h("b", { text: STATUS_SYM[l[0]] }), l[0] + " — " + l[1]);
          }))
        ]);
        schedule(complianceView);
      });
    }).catch(fail);
  }

  // ── Router ───────────────────────────────────────────────────────────────
  function route() {
    var hsh = location.hash || "#/";
    var m = hsh.match(/^#\/node\/(.+)$/);
    show(h("div", { class: "loading", text: "Loading…" }));
    if (m) return nodeView(decodeURIComponent(m[1]));
    if (hsh.indexOf("#/compliance") === 0) return complianceView();
    return fleetView();
  }
  window.addEventListener("hashchange", route);
  document.addEventListener("visibilitychange", function () { if (!document.hidden && !document.getElementById("login-form")) route(); });
  document.getElementById("logout").addEventListener("click", function () {
    api("/api/v1/logout", { method: "POST", body: {} }).then(loginView, loginView);
  });
  api("/api/v1/me").then(function (me) { document.getElementById("who").textContent = me.user; route(); }).catch(function () { /* login shown */ });
})();
