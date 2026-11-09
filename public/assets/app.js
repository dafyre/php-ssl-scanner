(function () {
  'use strict';

  // Ask before destructive actions (forms marked with data-confirm).
  document.querySelectorAll('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (e) {
      if (!window.confirm(f.dataset.confirm)) e.preventDefault();
    });
  });

  var form = document.getElementById('scan-form');
  if (form && window.fetch && window.FormData) {
    initScanProgress(form);
  }

  // Run the scan in the background and poll progress.php for live status. Without
  // JavaScript the form still works as a normal post; it just has no progress bar.
  function initScanProgress(form) {
    var button = document.getElementById('scan-button');
    var panel = document.getElementById('scan-status');
    var text = document.getElementById('status-text');
    var detail = document.getElementById('status-detail');
    var bar = document.getElementById('progress-bar');
    var fill = document.getElementById('progress-fill');
    var cancel = document.getElementById('cancel-button');
    var errorBox = document.getElementById('scan-error');
    var running = null;

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      if (!running) start();
    });

    cancel.addEventListener('click', function () {
      if (!running) return;
      cancel.disabled = true;
      text.textContent = 'Cancelling… saving partial results.';
      var body = new FormData();
      body.append('id', running.id);
      body.append('csrf', form.elements.csrf.value);
      fetch('progress.php', { method: 'POST', body: body, credentials: 'same-origin' });
    });

    function start() {
      var id = randomId();
      var data = new FormData(form);
      data.append('scan_id', id);
      running = { id: id, timer: null };

      errorBox.hidden = true;
      button.disabled = true;
      button.textContent = 'Scanning…';
      cancel.disabled = false;
      panel.hidden = false;
      text.textContent = 'Preparing scan…';
      detail.textContent = '';
      setPercent(null);
      setFormLocked(true);
      setOldResultsHidden(true);

      running.timer = setTimeout(poll, 300);

      fetch('index.php', {
        method: 'POST',
        body: data,
        credentials: 'same-origin',
        headers: { 'X-Requested-With': 'fetch' }
      })
        .then(function (res) {
          if (!res.ok) throw new Error('the server responded with HTTP ' + res.status);
          return res.json();
        })
        .then(function (json) {
          stopPolling();
          text.textContent = 'Scan complete. Loading results…';
          setPercent(100);
          window.location.href = json.redirect || 'index.php';
        })
        .catch(function (err) {
          stopPolling();
          finish();
          errorBox.textContent = 'Lost contact with the scan (' + err.message + '). ' +
            'If it was still running on the server, reload this page in a minute to see its results.';
          errorBox.hidden = false;
        });
    }

    function poll() {
      if (!running) return;
      var current = running;
      fetch('progress.php?id=' + current.id, { credentials: 'same-origin', cache: 'no-store' })
        .then(function (res) { return res.json(); })
        .then(function (state) { if (running === current) render(state); })
        .catch(function () { /* transient; try again on the next tick */ })
        .then(function () {
          if (running === current) current.timer = setTimeout(poll, 700);
        });
    }

    function render(state) {
      if (state.status === 'preparing') {
        text.textContent = 'Resolving hostnames and preparing scan…';
        setPercent(null);
      } else if (state.status === 'scanning' || state.status === 'cancelling') {
        var pct = state.total > 0 ? Math.floor((state.done / state.total) * 100) : 0;
        setPercent(pct);
        if (state.status === 'cancelling' || cancel.disabled) {
          text.textContent = 'Cancelling… saving partial results.';
        } else {
          text.textContent = 'Checked ' + fmt(state.done) + ' of ' + fmt(state.total) +
            ' address/port combinations (' + pct + '%)';
        }
        var parts = [
          fmt(state.found) + (state.found === 1 ? ' certificate' : ' certificates') + ' found',
          duration(state.elapsed) + ' elapsed'
        ];
        // Checks finish in bursts (fast answers first, then a wave of timeouts), so only
        // estimate once there's enough history for the rate to mean something.
        if (state.done < state.total && state.elapsed >= 5 && state.done >= state.total * 0.05) {
          var remaining = (state.total - state.done) / (state.done / state.elapsed);
          parts.push('about ' + duration(remaining) + ' left');
        }
        detail.textContent = parts.join(' · ');
      }
    }

    function setPercent(pct) {
      if (pct === null) {
        bar.classList.add('indeterminate');
        bar.removeAttribute('aria-valuenow');
        fill.style.width = '';
      } else {
        bar.classList.remove('indeterminate');
        bar.setAttribute('aria-valuenow', String(pct));
        fill.style.width = pct + '%';
      }
    }

    function stopPolling() {
      if (running && running.timer) clearTimeout(running.timer);
    }

    function finish() {
      running = null;
      button.disabled = false;
      button.textContent = 'Scan';
      panel.hidden = true;
      setFormLocked(false);
      setOldResultsHidden(false);
    }

    // Hide the previous scan's results (and its warnings) so they aren't mistaken for the new scan's.
    function setOldResultsHidden(hidden) {
      document.querySelectorAll('main > .results, main > p.warning, main > p.error:not(#scan-error)').forEach(function (el) {
        el.hidden = hidden;
      });
    }

    function setFormLocked(locked) {
      form.elements.targets.readOnly = locked;
      form.elements.ports.readOnly = locked;
    }
  }

  function randomId() {
    var bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return Array.prototype.map.call(bytes, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }

  function fmt(n) {
    return Number(n || 0).toLocaleString();
  }

  function duration(seconds) {
    seconds = Math.max(0, Math.round(seconds));
    var m = Math.floor(seconds / 60), s = seconds % 60;
    return m > 0 ? m + 'm ' + (s < 10 ? '0' : '') + s + 's' : s + 's';
  }

  var table = document.getElementById('results');
  if (!table) {
    return;
  }

  initFilters(table);

  // Filter rows by search text, status, port, issuer, self-signed, and days to expiry.
  // The CSV download follows the filters: it exports exactly the rows on screen.
  function initFilters(table) {
    var rows = Array.prototype.slice.call(table.tBodies[0].rows);
    var search = document.getElementById('f-search');
    var port = document.getElementById('f-port');
    var issuer = document.getElementById('f-issuer');
    var self = document.getElementById('f-self');
    var within = document.getElementById('f-within');
    var chips = Array.prototype.slice.call(document.querySelectorAll('#filters .chip'));
    var count = document.getElementById('f-count');
    var clear = document.getElementById('f-clear');
    var noMatches = document.getElementById('no-matches');
    var exportRows = document.getElementById('export-rows');
    var exportButton = document.getElementById('export-button');
    var defaults = chips.map(function (c) { return c.getAttribute('aria-pressed'); });
    var debounce = null;

    chips.forEach(function (chip) {
      chip.addEventListener('click', function () {
        chip.setAttribute('aria-pressed', chip.getAttribute('aria-pressed') === 'true' ? 'false' : 'true');
        apply();
      });
    });
    [port, issuer, self].forEach(function (el) { el.addEventListener('change', apply); });
    [search, within].forEach(function (el) {
      el.addEventListener('input', function () {
        clearTimeout(debounce);
        debounce = setTimeout(apply, 120);
      });
    });
    clear.addEventListener('click', function () {
      search.value = '';
      port.value = issuer.value = self.value = within.value = '';
      chips.forEach(function (c, i) { c.setAttribute('aria-pressed', defaults[i]); });
      apply();
    });

    function apply() {
      var terms = search.value.toLowerCase().split(/\s+/).filter(Boolean);
      var statuses = {};
      chips.forEach(function (c) { statuses[c.dataset.status] = c.getAttribute('aria-pressed') === 'true'; });
      var maxDays = within.value === '' ? null : Number(within.value);
      var visible = [];

      rows.forEach(function (row) {
        var d = row.dataset;
        var show = statuses[d.status] &&
          (!port.value || d.port === port.value) &&
          (!issuer.value || d.issuer === issuer.value) &&
          (!self.value || d.self === self.value) &&
          (maxDays === null || (d.days !== '' && Number(d.days) <= maxDays)) &&
          terms.every(function (t) { return d.search.indexOf(t) !== -1; });
        row.hidden = !show;
        if (show) visible.push(d.index);
      });

      var isDefault = !terms.length && !port.value && !issuer.value && !self.value && maxDays === null &&
        chips.every(function (c, i) { return c.getAttribute('aria-pressed') === defaults[i]; });
      count.textContent = 'Showing ' + fmt(visible.length) + ' of ' + fmt(rows.length);
      clear.hidden = isDefault;
      noMatches.hidden = visible.length > 0;

      if (exportRows) {
        // Empty means "everything"; otherwise send the indexes of the rows on screen.
        exportRows.value = visible.length === rows.length ? '' : (visible.length ? visible.join(',') : 'none');
        exportButton.textContent = 'Download CSV (' + fmt(visible.length) + ')';
        exportButton.disabled = visible.length === 0;
      }
    }

    apply();
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
