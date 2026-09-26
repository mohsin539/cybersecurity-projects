/* VPN Tunnel Builder — small UI helpers (confirm dialogs, live status refresh). */
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", function () {
    // Confirm dialogs for destructive actions
    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
      form.addEventListener("submit", function (e) {
        if (!window.confirm(form.dataset.confirm)) {
          e.preventDefault();
          e.stopImmediatePropagation();
        }
      });
    });

    // Live status refresh on tunnel detail
    var box = document.getElementById("status-box");
    var button = document.getElementById("refresh-status");
    if (box && box.dataset.interface) {
      var iface = box.dataset.interface;
      var fetchStatus = function () {
        fetch("/api/status/" + encodeURIComponent(iface), {
          headers: { "Accept": "application/json" }
        })
          .then(function (r) { return r.json(); })
          .then(function (data) { renderStatus(box, data); })
          .catch(function () { /* keep last good */ });
      };
      if (button) { button.addEventListener("click", fetchStatus); }
      var interval = parseInt(box.dataset.refresh || "0", 10);
      if (interval > 0) { window.setInterval(fetchStatus, interval * 1000); }
    }

    function renderStatus(box, data) {
      if (!data || typeof data !== "object") { return; }
      var running = !!data.running;
      var html = "";
      if (running) {
        html += '<div class="banner ok">Interface is UP</div>';
      } else {
        html += '<div class="banner warn">Interface is DOWN' +
          (data.error ? " — " + escapeHtml(data.error) : "") + "</div>";
      }
      var peers = data.peers || [];
      if (peers.length) {
        html += "<table class=\"tbl small\"><thead><tr><th>Peer</th><th>Handshake</th><th>RX</th><th>TX</th><th>Endpoint</th></tr></thead><tbody>";
        peers.forEach(function (p) {
          html += "<tr><td class=\"mono small\">" + escapeHtml((p.public_key || "").slice(0, 16)) +
            "…</td><td>" + escapeHtml(p.latest_handshake || "-") +
            "</td><td>" + escapeHtml(p.transfer_rx || "-") +
            "</td><td>" + escapeHtml(p.transfer_tx || "-") +
            "</td><td>" + escapeHtml(p.endpoint || "-") + "</td></tr>";
        });
        html += "</tbody></table>";
      } else {
        html += '<p class="muted">No active peer sessions.</p>';
      }
      box.innerHTML = html;
    }

    function escapeHtml(s) {
      return String(s).replace(/[&<>"']/g, function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
      });
    }
  });
})();