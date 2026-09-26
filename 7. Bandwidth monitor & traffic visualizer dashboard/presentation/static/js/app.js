"use strict";

(function () {
  // ================================================================ State
  let trafficChart, ifaceChart, protoChart;
  let sparkIn, sparkOut;
  let gaugeIn, gaugeOut, procChart;
  let selectedInterface = "total";
  let historyRange = 300;
  let connectionsTimer = null;
  let alertThresholds = { download_bps: 0, upload_bps: 0 };
  const MAX_HISTORY = 1200; // client-side ring size per series
  const SPARK_MAX = 60;

  const trafficHistory = { times: [], download: [], upload: [] };
  const sparkHistory = { dl: [], ul: [] };

  // Seed/reload bookkeeping: when a history range is fetched we keep the
  // seeded series and let the next live tick *append* to it instead of
  // replacing it with a single lonely point.
  let reloading = false;
  let historySeeded = false;

  // Feed health: the WS is primary; if it stalls we fall back to polling.
  let lastTelemetryAt = 0;
  const STALE_MS = 5000;
  const FALLBACK_POLL_MS = 3000;

  // Alert de-duplication (polled /api/current replays recent alerts).
  const alertKeys = new Set();

  // ================================================================ DOM
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);

  const dom = {
    wsStatus: $("#ws-status"),
    wsStatusText: $("#ws-status-text"),
    serverInfo: $("#server-info"),
    version: $("#version"),
    clock: $("#clock"),
    uptime: $("#uptime"),
    liveBadge: $(".live-badge"),
    kpiDownload: $("#kpi-download"),
    kpiUpload: $("#kpi-upload"),
    kpiDownloadTotal: $("#kpi-download-total"),
    kpiUploadTotal: $("#kpi-upload-total"),
    kpiRxTotal: $("#kpi-rx"),
    kpiTxTotal: $("#kpi-tx"),
    kpiRxPackets: $("#kpi-rx-packets"),
    kpiTxPackets: $("#kpi-tx-packets"),
    summaryLine: $("#summary-line"),
    chartTitle: $("#chart-title"),
    interfaceSelect: $("#interface-select"),
    rangeSelect: $("#range-select"),
    interfaceList: $("#interface-list"),
    connCount: $("#conn-count"),
    connBody: $("#conn-table tbody"),
    alertFeed: $("#alert-feed"),
    toast: $("#toast"),
    gaugeInValue: $("#gauge-in-value"),
    gaugeOutValue: $("#gauge-out-value"),
    gaugeInPeak: $("#gauge-in-peak"),
    gaugeOutPeak: $("#gauge-out-peak"),
    procMeta: $("#proc-meta"),
  };

  // ================================================================ Utils
  function toast(msg, ms = 2500) {
    dom.toast.textContent = msg;
    dom.toast.classList.remove("hidden");
    clearTimeout(toast._t);
    toast._t = setTimeout(() => dom.toast.classList.add("hidden"), ms);
  }

  function pushRing(arr, val, cap) {
    arr.push(val);
    if (arr.length > cap) arr.splice(0, arr.length - cap);
  }

  function resetTrafficHistory() {
    trafficHistory.times.length = 0;
    trafficHistory.download.length = 0;
    trafficHistory.upload.length = 0;
    historySeeded = false;
  }

  function toggleRange(lock) {
    if (lock) {
      document.body.classList.add("locked");
      $$(".kpi-grid, .chart-card, .grid-two").forEach(
        (e) => (e.style.opacity = "0.3")
      );
    } else {
      document.body.classList.remove("locked");
      $$(".kpi-grid, .chart-card, .grid-two").forEach(
        (e) => (e.style.opacity = "")
      );
    }
  }

  // ================================================================ Fetch helpers
  async function api(path, init) {
    try {
      const res = await fetch(path, init);
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      return res.json();
    } catch (err) {
      console.warn("API fetch failed:", path, err);
      return null;
    }
  }

  // ================================================================ Web socket
  function connectWs() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const url = `${proto}://${location.host}/ws`;
    const ws = new WebSocket(url);

    ws.onopen = () => {
      dom.wsStatus.className = "conn-status online";
      dom.wsStatusText.textContent = "connected";
      if (dom.liveBadge) dom.liveBadge.classList.remove("stale");
    };

    ws.onclose = () => {
      dom.wsStatus.className = "conn-status offline";
      dom.wsStatusText.textContent = "disconnected";
      setTimeout(connectWs, 2500);
    };

    ws.onerror = () => {};

    ws.onmessage = (evt) => {
      if (evt.type !== "message") return;
      let msg;
      try {
        msg = JSON.parse(evt.data);
      } catch {
        return;
      }
      if (msg.type === "telemetry") handleTelemetry(msg);
    };
  }

  // ================================================================ Telemetry
  function handleTelemetry(msg) {
    const { totals, interfaces, alerts, ts } = msg;

    if (!totals) return;
    lastTelemetryAt = Date.now();
    if (dom.liveBadge) dom.liveBadge.classList.remove("stale");

    // --- KPIs
    const dl = totals.download || 0;
    const ul = totals.upload || 0;
    dom.kpiDownload.textContent = Format.ratePerSecond(dl * 8, 1);
    dom.kpiUpload.textContent = Format.ratePerSecond(ul * 8, 1);

    // --- Gauges (bits/s; red segment + tick beyond alert threshold)
    if (gaugeIn && gaugeOut) {
      ChartFactory.setGaugeValue(gaugeIn, dl * 8);
      ChartFactory.setGaugeValue(gaugeOut, ul * 8);
      dom.gaugeInValue.textContent = `${Format.bits(dl * 8, 1)}/s`;
      dom.gaugeOutValue.textContent = `${Format.bits(ul * 8, 1)}/s`;
      dom.gaugeInPeak.textContent = `peak ${Format.bits(gaugeIn.$gauge.peak)}/s`;
      dom.gaugeOutPeak.textContent = `peak ${Format.bits(gaugeOut.$gauge.peak)}/s`;
    }

    if (dom.kpiDownloadTotal) {
      dom.kpiDownloadTotal.textContent = `${Format.bytes(totals.rx_bytes || 0)} received`;
    }
    if (dom.kpiUploadTotal) {
      dom.kpiUploadTotal.textContent = `${Format.bytes(totals.tx_bytes || 0)} sent`;
    }
    dom.kpiRxTotal.textContent = Format.bytes(totals.rx_bytes || 0);
    dom.kpiTxTotal.textContent = Format.bytes(totals.tx_bytes || 0);
    dom.kpiRxPackets.textContent = `${Format.number(totals.rx_packets || 0)} packets`;
    dom.kpiTxPackets.textContent = `${Format.number(totals.tx_packets || 0)} packets`;

    pushRing(sparkHistory.dl, dl, SPARK_MAX);
    pushRing(sparkHistory.ul, ul, SPARK_MAX);
    sparkIn.data.datasets[0].data = sparkHistory.dl;
    sparkOut.data.datasets[0].data = sparkHistory.ul;
    sparkIn.update("none");
    sparkOut.update("none");

    // --- Traffic chart
    // While a history fetch is in flight the seed will overwrite the series;
    // skip live appends so we don't interleave points from the old range.
    if (!reloading) {
      const point = pointForSelected(interfaces || [], dl, ul, ts);
      if (point) {
        if (historySeeded) {
          // First live tick after a seeded history: append, don't replace.
          historySeeded = false;
        }
        pushRing(trafficHistory.times, point.time, MAX_HISTORY);
        pushRing(trafficHistory.download, point.download, MAX_HISTORY);
        pushRing(trafficHistory.upload, point.upload, MAX_HISTORY);
        trafficChart.data.labels = trafficHistory.times;
        trafficChart.data.datasets[0].data = trafficHistory.download;
        trafficChart.data.datasets[1].data = trafficHistory.upload;
        trafficChart.update("none");
      }
    }

    // --- Interface breakdown bar
    const topIfaces = (interfaces || []).slice(0, 8);
    ifaceChart.data.labels = topIfaces.map((i) => i.name);
    ifaceChart.data.datasets[0].data = topIfaces.map((i) => i.download || 0);
    ifaceChart.data.datasets[1].data = topIfaces.map((i) => i.upload || 0);
    ifaceChart.update("none");

    // --- Sidebar interface list
    refreshInterfaceList(interfaces || []);

    // --- Summary
    const now = Format.epochToClock(ts);
    dom.summaryLine.textContent =
      `${(interfaces || []).length} interfaces  •  ${now}`;

    // --- Alerts
    if (alerts && alerts.length) {
      alerts.forEach((a) => pushAlert(a));
    }
  }

  function pointForSelected(interfaces, dl, ul, ts) {
    const timeLabel = new Date(ts * 1000).toLocaleTimeString();
    if (selectedInterface === "total") {
      return { time: timeLabel, download: dl, upload: ul };
    }
    const iface = interfaces.find((i) => i.name === selectedInterface);
    if (!iface) return null;
    return { time: timeLabel, download: iface.download || 0, upload: iface.upload || 0 };
  }

  function refreshInterfaceList(interfaces) {
    // Keep the select in sync (adds "total" first and any new interfaces).
    const existing = new Set(
      Array.from(dom.interfaceSelect.options).map((o) => o.value)
    );
    if (!existing.has("total")) {
      dom.interfaceSelect.insertAdjacentHTML(
        "afterbegin",
        '<option value="total" selected>All Interfaces</option>'
      );
      existing.add("total");
    }
    interfaces.forEach((i) => {
      if (!existing.has(i.name)) {
        const opt = document.createElement("option");
        opt.value = i.name;
        opt.textContent = i.name;
        dom.interfaceSelect.appendChild(opt);
        existing.add(i.name);
      }
    });

    // Sidebar list
    let html = "";
    interfaces.forEach((i) => {
      const active = i.name === selectedInterface ? " active" : "";
      const dl = Format.bits((i.download || 0) * 8, 1);
      const ul = Format.bits((i.upload || 0) * 8, 1);
      html += `<li class="${active}" data-iface="${i.name}">
        <span class="iface-name">${i.name}</span>
        <span class="iface-rate"><b>↓</b> ${dl}/s<br/><b>↑</b> ${ul}/s</span>
      </li>`;
    });
    dom.interfaceList.innerHTML = html || '<li class="empty-note">No data</li>';
  }

  // ================================================================ Alerts
  function pushAlert(a) {
    const key = `${a.timestamp}|${a.source}|${a.message}`;
    if (alertKeys.has(key)) return;
    alertKeys.add(key);
    if (alertKeys.size > 500) alertKeys.clear();

    const li = document.createElement("li");
    if (a.severity === "critical") li.className = "critical";
    li.innerHTML = `<div class="a-msg"><strong>${a.severity.toUpperCase()}</strong> ${a.source}: ${a.message}</div>
      <div class="a-time">${Format.epochToClock(a.timestamp)} • ${Format.bits(a.value_bps)}/s</div>`;
    dom.alertFeed.prepend(li);
    // Cap list size
    while (dom.alertFeed.children.length > 80) {
      dom.alertFeed.removeChild(dom.alertFeed.lastChild);
    }
  }

  // ================================================================ Connections (polled)
  let connPolling = false;
  function startConnectionPoll() {
    if (connPolling) return;
    connPolling = true;
    pollConnections();
    connectionsTimer = setInterval(pollConnections, 6000);
  }

  async function pollConnections() {
    const data = await api("/api/connections");
    if (!data) return;

    dom.connCount.textContent = `${data.total || 0} total`;

    // Protocol doughnut
    const labels = Object.keys(data.by_protocol || {});
    const values = Object.values(data.by_protocol || {});
    protoChart.data.labels = labels.map((l) => l.toUpperCase());
    protoChart.data.datasets[0].data = values;
    protoChart.update("none");

    // Top processes
    const procs = data.top_processes || [];
    const procsHtml = procs
      .map((p) => `<li><b>${p.name}</b> <span>${p.count}</span></li>`)
      .join("");
    const pl = document.getElementById("process-list");
    pl.innerHTML = procsHtml || '<li class="empty-note">No process data</li>';

    // Connections table
    const conns = data.connections || [];
    let tbody = "";
    conns.forEach((c) => {
      const protoClass = c.proto === "tcp" ? "proto-tcp" : "proto-udp";
      tbody += `<tr>
        <td>${esc(c.process || "—")}</td>
        <td class="${protoClass}">${(c.proto || "").toUpperCase()}</td>
        <td><span class="state">${esc(c.state || "—")}</span></td>
        <td>${esc(c.local || "—")}</td>
        <td>${esc(c.remote || "—")}</td>
      </tr>`;
    });
    dom.connBody.innerHTML =
      tbody || '<tr><td colspan="5" class="empty-note">No connections</td></tr>';
  }

  function esc(s) {
    if (!s) return "";
    const el = document.createElement("span");
    el.textContent = s;
    return el.innerHTML;
  }

  // ================================================================ Per-process bandwidth (polled)
  async function pollProcesses() {
    if (!procChart) return;
    const data = await api("/api/processes?limit=8");
    if (!data) return;
    if (data.enabled === false) {
      dom.procMeta.textContent = "attribution disabled";
      return;
    }
    const rows = data.processes || [];
    if (!rows.length) {
      dom.procMeta.textContent = data.sample_count
        ? "waiting for deltas…"
        : "collecting baseline…";
      return;
    }
    dom.procMeta.textContent = `top ${rows.length} of ${data.sample_count} samples`;
    procChart.data.labels = rows.map((r) =>
      r.name.length > 26 ? `${r.name.slice(0, 25)}…` : r.name
    );
    procChart.data.datasets[0].data = rows.map((r) => r.rate_recv || 0);
    procChart.data.datasets[1].data = rows.map((r) => r.rate_sent || 0);
    procChart.update("none");
  }

  // ================================================================ Feed health (WS fallback + stale badge)
  function startFeedWatchdog() {
    setInterval(async () => {
      const silentFor = Date.now() - lastTelemetryAt;
      if (silentFor > STALE_MS) {
        dom.liveBadge.classList.add("stale");
        // WebSocket stalled/absent -> poll the snapshot endpoint so the
        // dashboard keeps moving even without a live socket.
        const data = await api("/api/current");
        if (data && data.has_data) handleTelemetry(data);
      }
    }, FALLBACK_POLL_MS);
  }

  async function pollUptime() {
    const health = await api("/api/health");
    if (!health) return;
    dom.uptime.textContent = Format.duration(health.uptime_seconds || 0);
  }

  // ================================================================ History reload
  async function reloadHistory() {
    reloading = true;
    toggleRange(true);
    const data = await api(
      `/api/history?interface=${selectedInterface}&range_seconds=${historyRange}`
    );
    toggleRange(false);
    reloading = false;
    if (!data) {
      resetTrafficHistory();
      return;
    }

    dom.chartTitle.textContent = `Traffic — ${data.interface}`;

    if ((data.sample_count || 0) > 0) {
      // Seed the chart AND the client-side ring so the next live tick
      // appends to a continuous series instead of wiping the window.
      const labels = (data.timestamps || []).map(
        (ts) => new Date(ts * 1000).toLocaleTimeString()
      );
      trafficHistory.times = labels.slice(-MAX_HISTORY);
      trafficHistory.download = (data.download || []).slice(-MAX_HISTORY);
      trafficHistory.upload = (data.upload || []).slice(-MAX_HISTORY);
      historySeeded = true;
      ChartFactory.setTrafficData(trafficChart, data);
    } else {
      resetTrafficHistory();
      trafficChart.data.labels = [];
      trafficChart.data.datasets[0].data = [];
      trafficChart.data.datasets[1].data = [];
      trafficChart.update("none");
    }
  }

  // ================================================================ Events
  function bindEvents() {
    dom.interfaceSelect.addEventListener("change", () => {
      selectedInterface = dom.interfaceSelect.value;
      resetTrafficHistory();
      reloadHistory();
    });

    dom.rangeSelect.addEventListener("change", () => {
      historyRange = parseInt(dom.rangeSelect.value, 10) || 300;
      resetTrafficHistory();
      reloadHistory();
    });

    $("#refresh-btn").addEventListener("click", () => {
      reloadHistory();
      toast("History refreshed");
    });

    dom.interfaceList.addEventListener("click", (e) => {
      const li = e.target.closest("li[data-iface]");
      if (!li) return;
      selectedInterface = li.dataset.iface;
      dom.interfaceSelect.value = selectedInterface;
      resetTrafficHistory();
      reloadHistory();
    });

    $("#clear-alerts").addEventListener("click", () => {
      dom.alertFeed.innerHTML = "";
      alertKeys.clear();
      toast("Alerts cleared");
    });
  }

  // ================================================================ Bootstrap
  async function bootstrap() {
    // Initialise charts
    trafficChart = ChartFactory.trafficChart($("#traffic-chart"));
    sparkIn = ChartFactory.sparkline($("#spark-in"), ChartFactory.IN);
    sparkOut = ChartFactory.sparkline($("#spark-out"), ChartFactory.OUT);
    ifaceChart = ChartFactory.interfaceBar($("#iface-chart"));
    protoChart = ChartFactory.doughnut($("#proto-chart"));
    gaugeIn = ChartFactory.gauge($("#gauge-in"), ChartFactory.IN);
    gaugeOut = ChartFactory.gauge($("#gauge-out"), ChartFactory.OUT);
    procChart = ChartFactory.processBar($("#proc-chart"));

    // Load config (alert thresholds go on the sidebar card tooltip)
    const cfg = await api("/api/config");
    if (cfg) {
      dom.version.textContent = `v${cfg.version}`;
      if (cfg.alerts) {
        alertThresholds = cfg.alerts;
        ChartFactory.setGaugeThreshold(gaugeIn, cfg.alerts.download_bps);
        ChartFactory.setGaugeThreshold(gaugeOut, cfg.alerts.upload_bps);
        dom.serverInfo.title =
          `Alert thresholds — download: ${Format.bits(cfg.alerts.download_bps)}/s, ` +
          `upload: ${Format.bits(cfg.alerts.upload_bps)}/s`;
      }
    }

    // Preload history
    await reloadHistory();
    startConnectionPoll();
    pollProcesses();
    setInterval(pollProcesses, 6000);

    bindEvents();
    connectWs();
    startFeedWatchdog();
    pollUptime();
    setInterval(pollUptime, 5000);

    // E2E/test hooks (read-only introspection surface)
    window.__bwmon = {
      version: cfg ? cfg.version : null,
      wsConnected: () => dom.wsStatus.classList.contains("online"),
      lastTelemetryAt: () => lastTelemetryAt,
      ingest: handleTelemetry,
      charts: {
        traffic: trafficChart,
        interface: ifaceChart,
        protocol: protoChart,
        processes: procChart,
        gaugeIn,
        gaugeOut,
      },
    };

    // Clock + connection summary
    setInterval(() => {
      dom.clock.textContent = new Date().toLocaleTimeString();
      const latest = trafficChart.data.labels?.length
        ? trafficChart.data.labels[trafficChart.data.labels.length - 1]
        : "—";
      dom.serverInfo.textContent = dom.wsStatus.classList.contains("online")
        ? `live • last point: ${latest}`
        : `polling • last point: ${latest}`;
    }, 1000);
  }

  document.addEventListener("DOMContentLoaded", bootstrap);
})();
