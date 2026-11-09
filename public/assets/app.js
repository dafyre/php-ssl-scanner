(function () {
  'use strict';

  // Show a progress note and prevent double submits while a scan runs.
  var form = document.getElementById('scan-form');
  if (form) {
    form.addEventListener('submit', function () {
      var button = document.getElementById('scan-button');
      button.disabled = true;
      button.textContent = 'Scanning…';
      document.getElementById('scan-progress').hidden = false;
    });
  }

  var table = document.getElementById('results');
  if (!table) {
    return;
  }

  // Toggle rows for addresses that returned no certificate.
  var toggle = document.getElementById('show-failures');
  if (toggle) {
    toggle.addEventListener('change', function () {
      table.classList.toggle('hide-failures', !toggle.checked);
    });
  }

  // Click a column header to sort; click again to reverse.
  function ipKey(ip) {
    if (!ip) return '';
    if (ip.indexOf(':') === -1) {
      return ip.split('.').map(function (o) { return ('00' + o).slice(-3); }).join('.');
    }
    return ip;
  }

  var headers = table.querySelectorAll('th[data-sort]');
  headers.forEach(function (th) {
    th.tabIndex = 0;
    th.addEventListener('click', sort);
    th.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); sort.call(th); }
    });
  });

  function sort() {
    var th = this;
    var index = Array.prototype.indexOf.call(th.parentNode.children, th);
    var type = th.dataset.sort;
    var asc = th.getAttribute('aria-sort') !== 'ascending';
    headers.forEach(function (h) { h.removeAttribute('aria-sort'); });
    th.setAttribute('aria-sort', asc ? 'ascending' : 'descending');

    var body = table.tBodies[0];
    var rows = Array.prototype.slice.call(body.rows);
    rows.sort(function (a, b) {
      // Rows without a certificate always sink to the bottom.
      var aFail = a.classList.contains('none'), bFail = b.classList.contains('none');
      if (aFail !== bFail) return aFail ? 1 : -1;
      var av = value(a, index, type), bv = value(b, index, type);
      var cmp = av < bv ? -1 : av > bv ? 1 : 0;
      return asc ? cmp : -cmp;
    });
    rows.forEach(function (r) { body.appendChild(r); });
  }

  function value(row, index, type) {
    var cell = row.cells[index];
    if (!cell) return type === 'num' ? Infinity : '';
    var raw = cell.dataset.value !== undefined ? cell.dataset.value : cell.textContent.trim();
    if (type === 'num') return raw === '' ? Infinity : Number(raw);
    if (type === 'ip') return ipKey(raw);
    return raw.toLowerCase();
  }
})();
