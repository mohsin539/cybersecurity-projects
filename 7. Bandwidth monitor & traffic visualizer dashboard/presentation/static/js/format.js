"use strict";

const Format = (function () {
  function bits(bps, decimals = 2) {
    if (!isFinite(bps) || bps < 0) bps = 0;
    if (bps < 1000) return `${bps.toFixed(0)} bps`;
    const units = ["Kbps", "Mbps", "Gbps", "Tbps"];
    let value = bps;
    let unit = -1;
    do {
      value /= 1000;
      unit += 1;
    } while (value >= 1000 && unit < units.length - 1);
    return `${value.toFixed(decimals)} ${units[unit]}`;
  }

  function bytes(n, decimals = 1) {
    if (!isFinite(n) || n < 0) n = 0;
    if (n < 1024) return `${n.toFixed(0)} B`;
    const units = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    let value = n;
    let unit = -1;
    do {
      value /= 1024;
      unit += 1;
    } while (value >= 1024 && unit < units.length - 1);
    return `${value.toFixed(decimals)} ${units[unit]}`;
  }

  function ratePerSecond(bps, decimals = 1) {
    return `${bits(bps, decimals)}/s`;
  }

  function epochToClock(ts) {
    if (!ts) return "—";
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString();
  }

  function epochToTimeAgo(ts) {
    if (!ts) return "—";
    const secs = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (secs < 60) return `${secs}s ago`;
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    return `${hrs}h ${mins % 60}m ago`;
  }

  function duration(secs) {
    if (!secs) return "0s";
    secs = Math.floor(secs);
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    const parts = [];
    if (h) parts.push(`${h}h`);
    if (m) parts.push(`${m}m`);
    if (s || !parts.length) parts.push(`${s}s`);
    return parts.join(" ");
  }

  function number(n) {
    if (!isFinite(n)) return "0";
    return Number(n).toLocaleString();
  }

  return { bits, bytes, ratePerSecond, epochToClock, epochToTimeAgo, duration, number };
})();