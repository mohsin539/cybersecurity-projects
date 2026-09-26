"use strict";

const ChartFactory = (function () {
  const IN = "#10b981";
  const OUT = "#38bdf8";
  const GRID = "rgba(125, 139, 171, 0.12)";
  const TICK = "#7d8bab";

  const baseOptions = {
    responsive: true,
    maintainAspectRatio: false,
    animation: false,
    interaction: { mode: "nearest", intersect: false },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: "#0e1626",
        borderColor: "#1e2940",
        borderWidth: 1,
        titleColor: "#e6edf7",
        bodyColor: "#e6edf7",
        callbacks: {
          label(ctx) {
            const v = ctx.parsed.y ?? ctx.parsed;
            return `${ctx.dataset.label}: ${Format.bits(v * 8, 1)}/s`;
          },
        },
      },
    },
    scales: {
      x: {
        ticks: { color: TICK, maxTicksLimit: 8, maxRotation: 0 },
        grid: { color: "transparent" },
      },
      y: {
        ticks: {
          color: TICK,
          callback: (v) => Format.bits(v * 8, 0),
        },
        grid: { color: GRID, drawTicks: false },
        beginAtZero: true,
      },
    },
  };

  function trafficChart(canvas) {
    return new Chart(canvas, {
      type: "line",
      data: {
        datasets: [
          { label: "Download", data: [], borderColor: IN, backgroundColor: "rgba(16,185,129,0.10)", fill: true, borderWidth: 2, pointRadius: 0, tension: 0.3 },
          { label: "Upload", data: [], borderColor: OUT, backgroundColor: "rgba(56,189,248,0.08)", fill: true, borderWidth: 2, pointRadius: 0, tension: 0.3 },
        ],
      },
      options: {
        ...baseOptions,
        plugins: { ...baseOptions.plugins, legend: { display: false } },
      },
    });
  }

  function sparkline(canvas, color) {
    return new Chart(canvas, {
      type: "line",
      data: { datasets: [{ label: "rate", data: [], borderColor: color, borderWidth: 2, pointRadius: 0, fill: true, backgroundColor: "rgba(255,255,255,0.06)" }] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { display: false },
          y: { display: false, beginAtZero: true },
        },
      },
    });
  }

  function interfaceBar(canvas) {
    return new Chart(canvas, {
      type: "bar",
      data: {
        labels: [],
        datasets: [
          { label: "Download", data: [], backgroundColor: IN },
          { label: "Upload", data: [], backgroundColor: OUT },
        ],
      },
      options: {
        ...baseOptions,
        indexAxis: "y",
        plugins: {
          ...baseOptions.plugins,
          legend: { display: false },
        },
        scales: {
          x: {
            ticks: { color: TICK, callback: (v) => Format.bits(v * 8, 0) },
            grid: { color: GRID },
            stacked: true,
            beginAtZero: true,
          },
          y: {
            ticks: { color: TICK },
            grid: { display: false },
            stacked: true,
          },
        },
      },
    });
  }

  function doughnut(canvas) {
    return new Chart(canvas, {
      type: "doughnut",
      data: { labels: [], datasets: [{ data: [], backgroundColor: [IN, OUT, "#a78bfa", "#f472b6", "#fbbf24", "#34d399", "#e2e8f0"] }] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        cutout: "62%",
        plugins: {
          legend: {
            position: "right",
            labels: { color: TICK, boxWidth: 10, padding: 10, font: { size: 11.5 } },
          },
          tooltip: {
            backgroundColor: "#0e1626",
            borderColor: "#1e2940",
            borderWidth: 1,
          },
        },
      },
    });
  }

  // Rebuild an XY chart from a history payload (byte/s series + timestamps).
  function setTrafficData(chart, payload) {
    const labels = (payload.timestamps || []).map((ts) =>
      new Date(ts * 1000).toLocaleTimeString()
    );
    chart.data.labels = labels;
    chart.data.datasets[0].data = payload.download || [];
    chart.data.datasets[1].data = payload.upload || [];
    chart.update();
  }

  // ================================================================ Gauge
  // Semi-circular doughnut with a red zone beyond the alert threshold and an
  // exact threshold tick. Scale auto-grows: max = nice(max(peak, threshold) * 1.25).
  const thresholdMarkerPlugin = {
    id: "thresholdMarker",
    afterDatasetsDraw(chart) {
      const opts = chart.$gauge || {};
      const meta = chart.getDatasetMeta(0);
      const arc = meta.data[0];
      if (!arc) return;
      const props = arc.getProps(["x", "y", "outerRadius", "innerRadius"], true);
      const { x: cx, y: cy, outerRadius: ro, innerRadius: ri } = props;
      const ctx = chart.ctx;
      const fraction = Math.min(1, opts.threshold / opts.max || 0);

      // Red zone from the threshold to the scale maximum.
      if (fraction > 0 && fraction < 1) {
        ctx.save();
        ctx.beginPath();
        ctx.lineWidth = Math.max(3, (ro - ri) * 0.14);
        ctx.strokeStyle = "rgba(239, 68, 68, 0.85)";
        ctx.arc(cx, cy, (ro + ri) / 2, Math.PI + fraction * Math.PI, 2 * Math.PI);
        ctx.stroke();
        ctx.restore();
      }

      // Threshold tick.
      if (fraction > 0 && fraction < 1) {
        const theta = Math.PI + fraction * Math.PI;
        ctx.save();
        ctx.beginPath();
        ctx.lineWidth = 2;
        ctx.strokeStyle = "#ef4444";
        ctx.moveTo(cx + Math.cos(theta) * (ri - 2), cy + Math.sin(theta) * (ri - 2));
        ctx.lineTo(cx + Math.cos(theta) * (ro + 4), cy + Math.sin(theta) * (ro + 4));
        ctx.stroke();
        ctx.restore();
      }

      // Scale labels (0 left, max right).
      ctx.save();
      ctx.fillStyle = "#7d8bab";
      ctx.font = "10px 'Segoe UI', sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("0", cx - ro + 4, cy + 2);
      ctx.textAlign = "right";
      ctx.fillText(Format.bits(opts.max || 0, 0), cx + ro, cy + 2);
      ctx.restore();
    },
  };

  function niceCeil(v) {
    if (v <= 0) return 1;
    const exp = Math.floor(Math.log10(v));
    const base = Math.pow(10, exp);
    const n = v / base;
    const nice = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
    return nice * base;
  }

  function gauge(canvas, color) {
    const chart = new Chart(canvas, {
      type: "doughnut",
      data: {
        datasets: [
          {
            data: [0, 1],
            backgroundColor: [color, "rgba(255,255,255,0.06)"],
            borderWidth: 0,
            borderRadius: 6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        rotation: 270,
        circumference: 180,
        cutout: "72%",
        animation: { duration: 350 },
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
      },
      plugins: [thresholdMarkerPlugin],
    });
    chart.$gauge = { value: 0, peak: 0, threshold: 0, max: 1, color };
    return chart;
  }

  function setGaugeThreshold(chart, thresholdBps) {
    const g = chart.$gauge;
    g.threshold = Math.max(0, thresholdBps || 0);
    rescaleGauge(chart);
  }

  function setGaugeValue(chart, valueBps) {
    const g = chart.$gauge;
    g.value = Math.max(0, valueBps || 0);
    if (g.value > g.peak) g.peak = g.value;
    rescaleGauge(chart);
  }

  function rescaleGauge(chart) {
    const g = chart.$gauge;
    const target = Math.max(g.peak, g.threshold, g.value) * 1.25;
    g.max = niceCeil(target || 1);
    const filled = Math.min(1, g.value / g.max);
    // Above threshold: value segment turns red.
    const over = g.threshold > 0 && g.value >= g.threshold;
    chart.data.datasets[0].backgroundColor = [
      over ? "#ef4444" : g.color,
      "rgba(255,255,255,0.06)",
    ];
    chart.data.datasets[0].data = [filled, 1 - filled];
    chart.update();
  }

  // ================================================================ Process bandwidth bar
  function processBar(canvas) {
    return new Chart(canvas, {
      type: "bar",
      data: {
        labels: [],
        datasets: [
          { label: "Download", data: [], backgroundColor: IN },
          { label: "Upload", data: [], backgroundColor: OUT },
        ],
      },
      options: {
        ...baseOptions,
        indexAxis: "y",
        plugins: { ...baseOptions.plugins, legend: { display: false } },
        scales: {
          x: {
            stacked: true,
            beginAtZero: true,
            ticks: { color: TICK, callback: (v) => Format.bits(v * 8, 0) },
            grid: { color: GRID },
          },
          y: {
            stacked: true,
            ticks: { color: TICK, font: { size: 11 } },
            grid: { display: false },
          },
        },
      },
    });
  }

  return {
    IN,
    OUT,
    baseOptions,
    trafficChart,
    sparkline,
    interfaceBar,
    doughnut,
    setTrafficData,
    gauge,
    setGaugeThreshold,
    setGaugeValue,
    processBar,
  };
})();