document.addEventListener('DOMContentLoaded', function () {
  var audit = document.getElementById('audit');
  if (!audit) return;
  fetch('/api/audit')
    .then(function (r) { return r.json(); })
    .then(function (logs) {
      audit.innerHTML = logs.map(function (l) {
        return '<span class="chip ev"><b>' + l.actor + '</b> ' + l.action +
               ' <em>' + l.target + ' @ ' + l.at.replace('T', ' ').slice(0, 19) + '</em></span>';
      }).join('');
    })
    .catch(function () {
      audit.innerHTML = '<span class="chip dim">audit endpoint unavailable</span>';
    });
});