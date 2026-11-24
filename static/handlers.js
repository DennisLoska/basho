(function() {
  var MAX_POINTS = 60;
  var cpuData = [];
  var ramData = [];
  var gpuData = [];
  var ramTotal = 0;
  var gpuTotal = 0;
  var diskIOData = [];
  var diskIOMax = 1;

  // Security tab state (SSE lifecycle + client filters preserved across swaps)
  var securityEventSource = null;
  var securityRefreshTimer = null;
  var securityRefreshInFlight = false;
  var securityRefreshQueued = false;
  var securityAuthStopped = false;
  var securityReconnectTimer = null;
  var securityReconnectAttempt = 0;
  var SECURITY_RECONNECT_BASE_MS = 1000;
  var SECURITY_RECONNECT_MAX_MS = 30000;
  var securityCountdownInterval = null;
  var securityClockOffsetMs = 0;
  var securityClockSyncedEl = null;
  var securityFlashState = null;
  var SECURITY_FLASH_TTL_MS = 4000;
  var DIRTY_CONTROL_SELECTOR = '#security-mode-select, #scan-interval-input, [name^="criteria."], #security-test-channel';
  var securityDirtyControls = {};
  var securityState = {
    reachability: 'all',
    exposureSearch: '',
    eventCategory: 'all',
    hideNoise: true,
    openDetails: {},
  };
  var pendingFocusSnapshot = null;

  function normalizeTheme(theme) {
    if (theme === 'bumblebee' || theme === 'opencode-light' || theme === 'light') {
      return 'opencode-light';
    }
    return 'opencode';
  }

  function applyTheme(theme) {
    var html = document.documentElement;
    var sunIcon = document.getElementById('theme-icon-sun');
    var moonIcon = document.getElementById('theme-icon-moon');
    var metaTheme = document.getElementById('meta-theme-color');
    var normalized = normalizeTheme(theme);

    html.setAttribute('data-theme', normalized);
    try {
      localStorage.setItem('basho-theme', normalized);
      sessionStorage.setItem('basho-theme', normalized);
    } catch (e) {}

    if (metaTheme) {
      metaTheme.setAttribute('content', normalized === 'opencode' ? '#09090b' : '#f8f8fa');
    }
    if (sunIcon && moonIcon) {
      updateIcons(normalized, sunIcon, moonIcon);
    }
  }

  function syncActiveNav() {
    var path = window.location.pathname || '/';
    var items = document.querySelectorAll('[data-nav-path]');
    for (var i = 0; i < items.length; i++) {
      var itemPath = items[i].getAttribute('data-nav-path');
      var isActive = itemPath === '/'
        ? (path === '/' || path === '')
        : path.indexOf(itemPath) === 0;
      if (isActive) {
        items[i].classList.add('active');
        items[i].setAttribute('aria-current', 'page');
      } else {
        items[i].classList.remove('active');
        items[i].removeAttribute('aria-current');
      }
    }
  }

  function announceSecurityStatus(message, isError) {
    var el = document.getElementById('security-status-announcer');
    if (!el) return;
    var cls = isError
      ? 'oc-panel px-3.5 py-2.5 font-mono text-xs flex items-center justify-between gap-2 border-error/45 bg-error/10 text-error'
      : 'oc-panel px-3.5 py-2.5 font-mono text-xs flex items-center justify-between gap-2 border-info/45 bg-info/10 text-info';
    el.textContent = message;
    el.className = cls;
    if (message && message.trim()) {
      securityFlashState = {
        text: message.trim(),
        className: cls,
        expiresAt: Date.now() + SECURITY_FLASH_TTL_MS,
      };
    }
  }

  function recordVisibleFlashFromPanel(panel) {
    if (!panel) return;
    var el = panel.querySelector('#security-status-announcer');
    if (!el) return;
    var text = (el.textContent || '').trim();
    if (text && el.className.indexOf('sr-only') === -1) {
      securityFlashState = {
        text: text,
        className: el.className,
        expiresAt: Date.now() + SECURITY_FLASH_TTL_MS,
      };
    }
  }

  function controlDirtyKey(el) {
    return (el && (el.id || el.getAttribute('name'))) || '';
  }

  function markControlDirty(el) {
    if (!el || !el.matches || !el.matches(DIRTY_CONTROL_SELECTOR)) return;
    var key = controlDirtyKey(el);
    if (!key) return;
    securityDirtyControls[key] = {
      id: el.id || null,
      name: el.getAttribute('name') || null,
      value: el.value,
    };
  }

  function clearFormDirtyControls(form) {
    if (!form) {
      securityDirtyControls = {};
      return;
    }
    var controls = form.querySelectorAll(DIRTY_CONTROL_SELECTOR);
    for (var i = 0; i < controls.length; i++) {
      var key = controlDirtyKey(controls[i]);
      if (key) delete securityDirtyControls[key];
    }
  }

  function formatCountdownDuration(deltaMs) {
    if (!isFinite(deltaMs) || deltaMs <= 0) return 'due now';
    var totalSec = Math.ceil(deltaMs / 1000);
    var hours = Math.floor(totalSec / 3600);
    var mins = Math.floor((totalSec % 3600) / 60);
    var secs = totalSec % 60;
    if (hours > 0) return hours + 'h ' + mins + 'm';
    if (mins > 0) return mins + 'm ' + secs + 's';
    return secs + 's';
  }

  function syncSecurityClockOffset(el) {
    if (!el || securityClockSyncedEl === el) return;
    securityClockSyncedEl = el;
    var serverNowRaw = el.getAttribute('data-server-now');
    var serverNow = serverNowRaw ? Number(serverNowRaw) : NaN;
    if (isFinite(serverNow) && serverNow > 0) {
      var clockOffset = serverNow - Date.now();
      securityClockOffsetMs = clockOffset;
    } else {
      securityClockOffsetMs = 0;
    }
  }

  function stopSecurityCountdown() {
    if (securityCountdownInterval !== null) {
      clearInterval(securityCountdownInterval);
      securityCountdownInterval = null;
    }
    securityClockSyncedEl = null;
    securityClockOffsetMs = 0;
  }

  function updateSecurityNextScanCountdown() {
    var panel = document.getElementById('security-panel');
    if (!panel) {
      stopSecurityCountdown();
      return;
    }
    var el = panel.querySelector('[data-next-scan-at]');
    if (!el) return;
    syncSecurityClockOffset(el);
    if (el.getAttribute('data-scan-running') === 'true') {
      el.textContent = 'Scan running...';
      return;
    }
    var raw = el.getAttribute('data-next-scan-at');
    if (!raw) {
      el.textContent = 'Next scan: paused';
      return;
    }
    var targetMs = Number(raw);
    if (!isFinite(targetMs) || targetMs <= 0) {
      el.textContent = 'Next scan: paused';
      return;
    }
    el.textContent = 'Next scan: ' + formatCountdownDuration(targetMs - (Date.now() + securityClockOffsetMs));
  }

  function startSecurityCountdown() {
    if (!document.getElementById('security-panel')) {
      stopSecurityCountdown();
      return;
    }
    updateSecurityNextScanCountdown();
    if (securityCountdownInterval === null) {
      securityCountdownInterval = setInterval(updateSecurityNextScanCountdown, 1000);
    }
  }

  function captureSecurityState() {
    var panel = document.getElementById('security-panel');
    if (!panel) return null;

    var reachEl = panel.querySelector('[data-exposure-reachability]');
    if (reachEl) securityState.reachability = reachEl.value || 'all';

    var searchEl = panel.querySelector('[data-exposure-search]');
    if (searchEl) securityState.exposureSearch = searchEl.value || '';

    var hideNoiseEl = panel.querySelector('[data-hide-noise]');
    if (hideNoiseEl) securityState.hideNoise = !!hideNoiseEl.checked;

    var openMap = {};
    var details = panel.querySelectorAll('details[data-detail-id]');
    for (var i = 0; i < details.length; i++) {
      var id = details[i].getAttribute('data-detail-id');
      if (id && details[i].open) openMap[id] = true;
    }
    securityState.openDetails = openMap;

    var active = document.activeElement;
    var focusInfo = null;
    if (active && panel.contains(active)) {
      focusInfo = {
        id: active.id || null,
        name: active.getAttribute('name') || null,
        tagName: active.tagName || null,
        selectionStart: typeof active.selectionStart === 'number' ? active.selectionStart : null,
        selectionEnd: typeof active.selectionEnd === 'number' ? active.selectionEnd : null,
      };
    }
    return focusInfo;
  }

  function applySecurityFilters() {
    var panel = document.getElementById('security-panel');
    if (!panel) return;

    var reachFilter = (securityState.reachability || 'all').toLowerCase();
    var query = (securityState.exposureSearch || '').trim().toLowerCase();
    var exposureRows = panel.querySelectorAll('[data-exposure-row]');
    for (var i = 0; i < exposureRows.length; i++) {
      var row = exposureRows[i];
      var rowReach = (row.getAttribute('data-reachability') || '').toLowerCase();
      var rowSearch = (row.getAttribute('data-search') || '').toLowerCase();
      var reachOk = reachFilter === 'all' || rowReach === reachFilter;
      var queryOk = !query || rowSearch.indexOf(query) !== -1;
      row.style.display = (reachOk && queryOk) ? '' : 'none';
    }

    var activeCategory = (securityState.eventCategory || 'all').toLowerCase();
    var hideNoise = !!securityState.hideNoise;
    var chips = panel.querySelectorAll('[data-event-category]');
    for (var c = 0; c < chips.length; c++) {
      var chip = chips[c];
      var isSelected = (chip.getAttribute('data-event-category') || '').toLowerCase() === activeCategory;
      chip.setAttribute('aria-pressed', isSelected ? 'true' : 'false');
      chip.className = isSelected
        ? 'h-7 px-2.5 rounded border font-mono text-[11px] font-semibold bg-primary/15 border-primary/45 text-primary cursor-pointer'
        : 'h-7 px-2.5 rounded border font-mono text-[11px] bg-base-100 border-base-300 text-base-content/70 hover:text-base-content cursor-pointer';
    }

    var eventRows = panel.querySelectorAll('[data-event-row]');
    for (var j = 0; j < eventRows.length; j++) {
      var evRow = eventRows[j];
      var evCat = (evRow.getAttribute('data-category') || '').toLowerCase();
      var isNoise = evRow.getAttribute('data-noise') === 'true';
      var catOk = activeCategory === 'all' || evCat === activeCategory;
      var noiseOk = !hideNoise || !isNoise;
      if (catOk && noiseOk) {
        evRow.classList.remove('hidden');
      } else {
        evRow.classList.add('hidden');
      }
    }
  }

  function restoreSecurityState(focusInfo, options) {
    var panel = document.getElementById('security-panel');
    if (!panel) return;
    var preserveFlash = !!(options && options.preserveFlash);

    var reachEl = panel.querySelector('[data-exposure-reachability]');
    if (reachEl) reachEl.value = securityState.reachability || 'all';

    var searchEl = panel.querySelector('[data-exposure-search]');
    if (searchEl) searchEl.value = securityState.exposureSearch || '';

    var hideNoiseEl = panel.querySelector('[data-hide-noise]');
    if (hideNoiseEl) hideNoiseEl.checked = !!securityState.hideNoise;

    var details = panel.querySelectorAll('details[data-detail-id]');
    for (var i = 0; i < details.length; i++) {
      var id = details[i].getAttribute('data-detail-id');
      if (id && securityState.openDetails[id]) {
        details[i].open = true;
      }
    }

    var dirtyKeys = Object.keys(securityDirtyControls);
    for (var d = 0; d < dirtyKeys.length; d++) {
      var dirty = securityDirtyControls[dirtyKeys[d]];
      if (!dirty) continue;
      var ctrl = dirty.id ? document.getElementById(dirty.id) : null;
      if (!ctrl && dirty.name) {
        var named = panel.querySelectorAll('[name]');
        for (var n = 0; n < named.length; n++) {
          if (named[n].getAttribute('name') === dirty.name) {
            ctrl = named[n];
            break;
          }
        }
      }
      if (ctrl && panel.contains(ctrl)) {
        ctrl.value = dirty.value;
      }
    }

    if (preserveFlash && securityFlashState) {
      if (Date.now() < securityFlashState.expiresAt) {
        var announcer = panel.querySelector('#security-status-announcer');
        if (announcer && !(announcer.textContent || '').trim()) {
          announcer.textContent = securityFlashState.text;
          announcer.className = securityFlashState.className;
        }
      } else {
        securityFlashState = null;
      }
    }

    applySecurityFilters();
    updateSecurityNextScanCountdown();

    if (focusInfo) {
      var target = null;
      if (focusInfo.id) {
        target = document.getElementById(focusInfo.id);
      }
      if (!target && focusInfo.name && focusInfo.tagName) {
        var candidates = panel.querySelectorAll(focusInfo.tagName.toLowerCase() + '[name]');
        for (var k = 0; k < candidates.length; k++) {
          if (candidates[k].getAttribute('name') === focusInfo.name) {
            target = candidates[k];
            break;
          }
        }
      }
      if (target && panel.contains(target) && typeof target.focus === 'function') {
        try {
          target.focus({ preventScroll: true });
          if (
            focusInfo.selectionStart !== null &&
            focusInfo.selectionEnd !== null &&
            typeof target.setSelectionRange === 'function'
          ) {
            target.setSelectionRange(focusInfo.selectionStart, focusInfo.selectionEnd);
          }
        } catch (e) {}
      }
    }
  }

  function closeSecurityStream() {
    if (securityRefreshTimer !== null) {
      clearTimeout(securityRefreshTimer);
      securityRefreshTimer = null;
    }
    if (securityReconnectTimer !== null) {
      clearTimeout(securityReconnectTimer);
      securityReconnectTimer = null;
    }
    securityRefreshQueued = false;
    if (securityEventSource) {
      try {
        securityEventSource.close();
      } catch (e) {}
      securityEventSource = null;
    }
  }

  function scheduleSecurityReconnect() {
    if (securityAuthStopped || !document.querySelector('[data-security-stream]')) {
      return;
    }
    if (securityReconnectTimer !== null) return;
    var delay = Math.min(
      SECURITY_RECONNECT_MAX_MS,
      SECURITY_RECONNECT_BASE_MS * Math.pow(2, securityReconnectAttempt),
    );
    securityReconnectAttempt = Math.min(securityReconnectAttempt + 1, 10);
    securityReconnectTimer = setTimeout(function() {
      securityReconnectTimer = null;
      syncSecurityStream();
    }, delay);
  }

  function refreshSecurityFragment() {
    if (!document.querySelector('[data-security-stream]')) {
      closeSecurityStream();
      return;
    }
    if (securityAuthStopped) return;
    if (securityRefreshInFlight) {
      securityRefreshQueued = true;
      return;
    }

    securityRefreshInFlight = true;
    securityRefreshQueued = false;

    fetch('/security/fragment', {
      credentials: 'same-origin',
      headers: { 'HX-Request': 'true' },
      redirect: 'manual',
    })
      .then(function(response) {
        if (
          response.type === 'opaqueredirect' ||
          response.status === 401 ||
          response.status === 403 ||
          response.status === 302 ||
          response.status === 303
        ) {
          securityAuthStopped = true;
          closeSecurityStream();
          announceSecurityStatus('Security session expired. Sign in again to resume live updates.', true);
          return null;
        }
        if (!response.ok) {
          announceSecurityStatus('Unable to refresh security view (HTTP ' + response.status + ').', true);
          return null;
        }
        return response.text();
      })
      .then(function(htmlText) {
        if (htmlText === null) return;
        var currentPanel = document.getElementById('security-panel');
        if (!currentPanel) {
          closeSecurityStream();
          return;
        }

        var focusInfo = captureSecurityState();
        var tpl = document.createElement('template');
        tpl.innerHTML = htmlText;

        var nextPanel = tpl.content.querySelector('#security-panel');
        var nextDot = tpl.content.querySelector('#security-nav-dot');

        if (nextPanel && currentPanel.parentNode) {
          currentPanel.parentNode.replaceChild(nextPanel, currentPanel);
          if (window.htmx && typeof window.htmx.process === 'function') {
            window.htmx.process(nextPanel);
          }
        }
        if (nextDot) {
          nextDot.removeAttribute('hx-swap-oob');
          var existingDot = document.getElementById('security-nav-dot');
          if (existingDot && existingDot.parentNode) {
            existingDot.parentNode.replaceChild(nextDot, existingDot);
          }
        }

        restoreSecurityState(focusInfo, { preserveFlash: true });
      })
      .catch(function() {
        announceSecurityStatus('Unable to reach Basho Security service for live update.', true);
      })
      .finally(function() {
        securityRefreshInFlight = false;
        if (securityRefreshQueued && !securityAuthStopped) {
          scheduleSecurityRefresh();
        }
      });
  }

  function scheduleSecurityRefresh() {
    if (securityAuthStopped || !document.querySelector('[data-security-stream]')) {
      return;
    }
    if (securityRefreshTimer !== null) return;
    securityRefreshTimer = setTimeout(function() {
      securityRefreshTimer = null;
      refreshSecurityFragment();
    }, 150);
  }

  function syncSecurityStream() {
    var host = document.querySelector('[data-security-stream]');
    if (!host) {
      closeSecurityStream();
      stopSecurityCountdown();
      securityAuthStopped = false;
      securityReconnectAttempt = 0;
      securityFlashState = null;
      securityDirtyControls = {};
      return;
    }

    applySecurityFilters();
    startSecurityCountdown();

    if (securityAuthStopped) return;
    if (securityEventSource && securityEventSource.readyState !== 2) {
      return;
    }

    var streamUrl = host.getAttribute('data-security-stream') || '/sse/security';
    try {
      var es = new EventSource(streamUrl);
      securityEventSource = es;

      es.addEventListener('open', function() {
        if (securityEventSource !== es) return;
        securityReconnectAttempt = 0;
      });

      es.addEventListener('security', function() {
        if (securityEventSource !== es) return;
        securityReconnectAttempt = 0;
        scheduleSecurityRefresh();
      });

      es.addEventListener('error', function() {
        if (securityEventSource !== es) return;
        if (!document.querySelector('[data-security-stream]')) {
          closeSecurityStream();
          stopSecurityCountdown();
          return;
        }
        if (es.readyState === 2) {
          closeSecurityStream();
          // Verify whether auth expired; stop reconnecting if login is required.
          fetch('/security/fragment', {
            credentials: 'same-origin',
            headers: { 'HX-Request': 'true' },
            redirect: 'manual',
          })
            .then(function(res) {
              if (
                res.type === 'opaqueredirect' ||
                res.status === 401 ||
                res.status === 403 ||
                res.status === 302 ||
                res.status === 303
              ) {
                securityAuthStopped = true;
                announceSecurityStatus('Security session expired. Sign in again to resume live updates.', true);
                return;
              }
              if (res.status === 200) {
                announceSecurityStatus('Security live stream interrupted. Reconnecting...', true);
                scheduleSecurityReconnect();
                return;
              }
              announceSecurityStatus('Security live stream disconnected (HTTP ' + res.status + '). Reconnecting...', true);
              scheduleSecurityReconnect();
            })
            .catch(function() {
              announceSecurityStatus('Security live stream disconnected. Reconnecting...', true);
              scheduleSecurityReconnect();
            });
        }
      });
    } catch (e) {}
  }

  function init() {
    var html = document.documentElement;
    var savedTheme = null;
    try {
      savedTheme = localStorage.getItem('basho-theme') || sessionStorage.getItem('basho-theme');
    } catch (e) {}

    applyTheme(savedTheme || html.getAttribute('data-theme') || 'opencode');
    syncActiveNav();
    syncSecurityStream();

    window.toggleTheme = function() {
      var current = normalizeTheme(html.getAttribute('data-theme'));
      var next = current === 'opencode' ? 'opencode-light' : 'opencode';
      applyTheme(next);
    };
  }

  function updateIcons(theme, sun, moon) {
    if (theme === 'opencode') {
      sun.classList.remove('hidden');
      moon.classList.add('hidden');
    } else {
      sun.classList.add('hidden');
      moon.classList.remove('hidden');
    }
  }

  function pushData(arr, val) {
    arr.push(val);
    if (arr.length > MAX_POINTS) arr.shift();
  }

  var CX0 = 16, CX1 = 135, CY0 = 3, CY1 = 40;
  var CW = CX1 - CX0, CH = CY1 - CY0;

  function svgPath(data, max) {
    if (data.length < 2 || max <= 0) return '';
    var parts = [];
    for (var i = 0; i < data.length; i++) {
      var x = CX0 + (i / (data.length - 1)) * CW;
      var clamped = Math.max(0, Math.min(data[i], max));
      var y = CY1 - (clamped / max) * CH;
      parts.push((i === 0 ? 'M' : 'L') + x.toFixed(1) + ' ' + y.toFixed(1));
    }
    return parts.join(' ');
  }

  function svgFillPath(data, max) {
    if (data.length < 2 || max <= 0) return '';
    return svgPath(data, max) + ' L' + CX1.toFixed(1) + ' ' + CY1 + ' L' + CX0.toFixed(1) + ' ' + CY1 + ' Z';
  }

  function updateChart(id, data, max) {
    var line = document.getElementById(id + '-line');
    var fill = document.getElementById(id + '-fill');
    if (line) line.setAttribute('d', svgPath(data, max));
    if (fill) fill.setAttribute('d', svgFillPath(data, max));
  }

  function updateCpuCores(cores) {
    var grid = document.getElementById('cpu-cores-grid');
    if (!grid || !cores || !cores.length) return;
    if (grid.children.length !== cores.length) {
      grid.innerHTML = '';
      for (var i = 0; i < cores.length; i++) {
        var cell = document.createElement('div');
        cell.className = 'h-3 rounded-[2px] bg-base-300 overflow-hidden flex items-end';
        cell.title = 'Core ' + i;
        var fill = document.createElement('div');
        fill.className = 'w-full bg-accent/80 transition-all duration-300';
        fill.style.height = '0%';
        cell.appendChild(fill);
        grid.appendChild(cell);
      }
    }
    for (var j = 0; j < cores.length; j++) {
      var bar = grid.children[j] && grid.children[j].firstElementChild;
      if (bar) {
        var u = Math.max(4, Math.min(100, cores[j].usage || 0));
        bar.style.height = u + '%';
        grid.children[j].title = 'Core ' + j + ': ' + (cores[j].usage || 0) + '%';
      }
    }
  }

  function createDiskId(device) {
    return 'disk-' + device.replace(/[^a-zA-Z0-9]/g, '_');
  }

  function createDiskCard(id, disk) {
    var container = document.getElementById('disks-container');
    if (!container) return null;
    var card = document.createElement('section');
    card.className = 'oc-panel p-4 sm:p-5 flex flex-col justify-between';
    card.id = id;
    var label = disk.name || disk.device;
    var typeTag = disk.type && disk.type !== 'Unknown' ? disk.type : disk.device;
    card.innerHTML =
      '<div>' +
        '<div class="flex items-center justify-between gap-2 pb-3 border-b border-base-300/80">' +
          '<div class="flex items-center gap-2 min-w-0">' +
            '<span class="w-2 h-2 rounded-full bg-info animate-pulse shrink-0"></span>' +
            '<h3 class="font-mono text-xs sm:text-sm font-bold uppercase tracking-wider text-base-content truncate">' + label + '</h3>' +
          '</div>' +
          '<span class="font-mono text-[11px] px-2 py-0.5 rounded bg-base-300/70 text-base-content/70 shrink-0">' + typeTag + '</span>' +
        '</div>' +
        '<div id="' + id + '-info" class="mt-3">' +
          '<div class="flex items-baseline justify-between gap-2 flex-wrap">' +
            '<div class="text-3xl sm:text-4xl font-mono tabular-nums font-bold text-info tracking-tight" id="' + id + '-percent">' + disk.usePercent + '%</div>' +
            '<div class="text-xs sm:text-sm font-mono tabular-nums text-base-content/70">' +
              '<span id="' + id + '-used" class="text-base-content font-semibold">' + disk.used + '</span> / <span id="' + id + '-size">' + disk.totalSize + '</span> GB' +
            '</div>' +
          '</div>' +
          '<div class="h-2 bg-base-300 rounded-sm mt-2.5 overflow-hidden">' +
            '<div id="' + id + '-bar" class="h-full bg-info transition-all duration-500" style="width: ' + disk.usePercent + '%"></div>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="mt-4 pt-3 border-t border-base-300/50">' +
        '<svg class="w-full h-32 sm:h-40 block" id="' + id + '-chart" viewBox="0 0 137 45" preserveAspectRatio="none">' +
          '<defs>' +
            '<linearGradient id="' + id + '-grad" x1="0" y1="0" x2="0" y2="1">' +
              '<stop offset="0%" stop-color="var(--color-info)" stop-opacity="0.32"></stop>' +
              '<stop offset="100%" stop-color="var(--color-info)" stop-opacity="0.0"></stop>' +
            '</linearGradient>' +
          '</defs>' +
          '<line x1="16" y1="3" x2="135" y2="3" stroke="var(--color-base-content)" stroke-opacity="0.08" stroke-width="0.4" stroke-dasharray="1.5,1.5"></line>' +
          '<line x1="16" y1="3" x2="16" y2="40" stroke="var(--color-base-content)" stroke-opacity="0.18" stroke-width="0.6"></line>' +
          '<line x1="16" y1="21.5" x2="135" y2="21.5" stroke="var(--color-base-content)" stroke-opacity="0.12" stroke-width="0.4" stroke-dasharray="1.5,1.5"></line>' +
          '<line x1="16" y1="40" x2="135" y2="40" stroke="var(--color-base-content)" stroke-opacity="0.18" stroke-width="0.6"></line>' +
          '<text id="' + id + '-yl0" x="14" y="6" text-anchor="end" fill="var(--color-base-content)" fill-opacity="0.5" font-size="3.4" font-family="monospace">0</text>' +
          '<text id="' + id + '-yl1" x="14" y="22.8" text-anchor="end" fill="var(--color-base-content)" fill-opacity="0.5" font-size="3.4" font-family="monospace">0</text>' +
          '<text id="' + id + '-yl2" x="14" y="40.5" text-anchor="end" fill="var(--color-base-content)" fill-opacity="0.5" font-size="3.4" font-family="monospace">0</text>' +
          '<path id="' + id + '-fill" fill="url(#' + id + '-grad)" d=""></path>' +
          '<path id="' + id + '-line" fill="none" stroke="var(--color-info)" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" d=""></path>' +
        '</svg>' +
      '</div>';
    container.appendChild(card);
    return card;
  }

  document.addEventListener('change', function(evt) {
    var target = evt.target;
    if (!target) return;
    if (target.matches && target.matches('[data-exposure-reachability]')) {
      securityState.reachability = target.value || 'all';
      applySecurityFilters();
    } else if (target.matches && target.matches('[data-hide-noise]')) {
      securityState.hideNoise = !!target.checked;
      applySecurityFilters();
    } else if (target.matches && target.matches(DIRTY_CONTROL_SELECTOR)) {
      markControlDirty(target);
    }
  });

  document.addEventListener('input', function(evt) {
    var target = evt.target;
    if (!target || !target.matches) return;
    if (target.matches('[data-exposure-search]')) {
      securityState.exposureSearch = target.value || '';
      applySecurityFilters();
    } else if (target.matches(DIRTY_CONTROL_SELECTOR)) {
      markControlDirty(target);
    }
  });

  document.addEventListener('submit', function(evt) {
    var form = evt.target;
    if (form && form.closest && form.closest('#security-panel')) {
      clearFormDirtyControls(form);
    }
  });

  document.addEventListener('click', function(evt) {
    var target = evt.target && evt.target.closest ? evt.target.closest('[data-event-category]') : null;
    if (!target) return;
    securityState.eventCategory = target.getAttribute('data-event-category') || 'all';
    applySecurityFilters();
  });

  document.addEventListener('htmx:beforeRequest', function(evt) {
    var detail = evt.detail || {};
    var path = (detail.requestConfig && detail.requestConfig.path) || '';
    var verb = (detail.requestConfig && detail.requestConfig.verb) || '';
    if (path.indexOf('/security/') === 0 && verb.toLowerCase() === 'post') {
      var form = detail.elt && detail.elt.closest ? detail.elt.closest('form') : null;
      if (form) clearFormDirtyControls(form);
    }
  });

  document.addEventListener('htmx:beforeSwap', function(evt) {
    var detail = evt.detail || {};
    var xhr = detail.xhr;
    var reqPath = (detail.requestConfig && detail.requestConfig.path)
      || (detail.pathInfo && detail.pathInfo.requestPath)
      || '';
    if (
      xhr &&
      (xhr.status === 400 || xhr.status === 404 || xhr.status === 409) &&
      (reqPath.indexOf('/security/') === 0 || reqPath === '/security')
    ) {
      var body = typeof detail.serverResponse === 'string'
        ? detail.serverResponse
        : (xhr.responseText || '');
      if (body.indexOf('id="security-panel"') !== -1) {
        detail.shouldSwap = true;
        detail.isError = false;
      }
    }

    var target = detail.target;
    if (target && target.id === 'security-panel') {
      pendingFocusSnapshot = captureSecurityState();
      return;
    }
    cpuData = [];
    ramData = [];
    gpuData = [];
    diskIOData = [];
    diskIOMax = 1;
    ramTotal = 0;
    gpuTotal = 0;
  });

  document.addEventListener('htmx:afterSwap', function(evt) {
    var detail = evt.detail || {};
    var target = detail.target;
    var panel = document.getElementById('security-panel');
    if ((target && target.id === 'security-panel') || (panel && detail.elt && detail.elt.id === 'security-panel')) {
      recordVisibleFlashFromPanel(panel);
      restoreSecurityState(pendingFocusSnapshot, { preserveFlash: false });
      pendingFocusSnapshot = null;
    }
    syncSecurityStream();
  });

  document.addEventListener('htmx:afterRequest', function(evt) {
    var detail = evt.detail || {};
    var path = (detail.requestConfig && detail.requestConfig.path) || '';
    var verb = (detail.requestConfig && detail.requestConfig.verb) || '';
    if (detail.successful && path.indexOf('/security/') === 0 && verb.toLowerCase() === 'post') {
      var form = detail.elt && detail.elt.closest ? detail.elt.closest('form') : null;
      if (form) clearFormDirtyControls(form);
    }
  });

  document.addEventListener('htmx:afterSettle', function() {
    syncActiveNav();
    syncSecurityStream();
  });

  document.addEventListener('htmx:responseError', function(evt) {
    var xhr = evt.detail && evt.detail.xhr;
    var path = (evt.detail && evt.detail.requestConfig && evt.detail.requestConfig.path) || '';
    if (path.indexOf('/security') !== 0) return;
    var status = xhr ? xhr.status : 0;
    if (status === 401 || status === 403) {
      securityAuthStopped = true;
      closeSecurityStream();
      announceSecurityStatus('Security action rejected (HTTP ' + status + '). Sign in or reload to continue.', true);
      return;
    }
    var msg = (xhr && xhr.responseText && xhr.responseText.length < 200)
      ? xhr.responseText
      : 'Security request failed (HTTP ' + status + ').';
    announceSecurityStatus(msg, true);
  });

  document.addEventListener('htmx:sendError', function(evt) {
    var path = (evt.detail && evt.detail.requestConfig && evt.detail.requestConfig.path) || '';
    if (path.indexOf('/security') !== 0) return;
    announceSecurityStatus('Network error while contacting Basho Security.', true);
  });

  window.addEventListener('popstate', function() {
    syncActiveNav();
    syncSecurityStream();
  });

  function teardownSecurityPage() {
    closeSecurityStream();
    stopSecurityCountdown();
  }

  window.addEventListener('pagehide', teardownSecurityPage);
  window.addEventListener('beforeunload', teardownSecurityPage);

  document.addEventListener('htmx:sseBeforeMessage', function(evt) {
    evt.preventDefault();
    try {
      var data = JSON.parse(evt.detail.data);
      if (data.type !== 'system') return;

      // CPU
      var avg = document.getElementById('cpu-average');
      var quickCpu = document.getElementById('quick-cpu');
      var count = document.getElementById('cpu-count');
      var cbar = document.getElementById('cpu-bar');
      if (avg) avg.textContent = data.cpu.average + '%';
      if (quickCpu) quickCpu.textContent = data.cpu.average + '%';
      if (count) count.textContent = data.cpu.count + ' threads';
      if (cbar) cbar.style.width = data.cpu.average + '%';
      var cy0 = document.getElementById('cpu-yl-0');
      var cy1 = document.getElementById('cpu-yl-1');
      if (cy0) cy0.textContent = '100%';
      if (cy1) cy1.textContent = '50%';
      updateCpuCores(data.cpu.cores);
      pushData(cpuData, data.cpu.average);
      updateChart('cpu-chart', cpuData, 100);

      // RAM
      var rp = document.getElementById('ram-percent');
      var quickRam = document.getElementById('quick-ram');
      var quickRamSub = document.getElementById('quick-ram-sub');
      var ru = document.getElementById('ram-used');
      var rt = document.getElementById('ram-total');
      var rc = document.getElementById('ram-cached');
      var rb = document.getElementById('ram-bar');
      if (rp) rp.textContent = data.ram.percent + '%';
      if (quickRam) quickRam.textContent = data.ram.percent + '%';
      if (quickRamSub) quickRamSub.textContent = data.ram.used + 'G';
      if (ru) ru.textContent = data.ram.used;
      if (rt) { rt.textContent = data.ram.total; ramTotal = data.ram.total; }
      if (rc) rc.textContent = data.ram.cached;
      if (rb) rb.style.width = data.ram.percent + '%';
      var ry0 = document.getElementById('ram-yl-0');
      var ry1 = document.getElementById('ram-yl-1');
      if (ry0) ry0.textContent = Math.round(ramTotal) + 'G';
      if (ry1) ry1.textContent = Math.round(ramTotal / 2) + 'G';
      pushData(ramData, data.ram.used);
      updateChart('ram-chart', ramData, ramTotal || 1);

      // Disks
      if (data.disks && data.disks.length) {
        var seenDisks = {};
        data.disks.forEach(function(disk) {
          var id = createDiskId(disk.device);
          seenDisks[id] = true;
          var card = document.getElementById(id);
          if (!card) card = createDiskCard(id, disk);
          if (!card) return;
          var pct = document.getElementById(id + '-percent');
          var used = document.getElementById(id + '-used');
          var size = document.getElementById(id + '-size');
          var bar = document.getElementById(id + '-bar');
          if (pct) pct.textContent = disk.usePercent + '%';
          if (used) used.textContent = disk.used;
          if (size) size.textContent = disk.totalSize;
          if (bar) bar.style.width = disk.usePercent + '%';
        });
        var container = document.getElementById('disks-container');
        if (container) {
          var cards = container.children;
          for (var i = cards.length - 1; i >= 0; i--) {
            if (!seenDisks[cards[i].id]) cards[i].remove();
          }
        }
      }

      if (data.diskIO) {
        var quickIo = document.getElementById('quick-io');
        var rIops = document.getElementById('disk-read-iops');
        var wIops = document.getElementById('disk-write-iops');
        if (quickIo) quickIo.textContent = data.diskIO.totalIO_sec;
        if (rIops) rIops.textContent = data.diskIO.readIO_sec;
        if (wIops) wIops.textContent = data.diskIO.writeIO_sec;

        pushData(diskIOData, data.diskIO.totalIO_sec);
        if (data.diskIO.totalIO_sec > diskIOMax) diskIOMax = data.diskIO.totalIO_sec;
        var chartMax = Math.ceil(diskIOMax * 1.2) || 1;
        if (data.disks) {
          data.disks.forEach(function(disk) {
            var id = createDiskId(disk.device);
            var yl0 = document.getElementById(id + '-yl0');
            var yl1 = document.getElementById(id + '-yl1');
            if (yl0) yl0.textContent = chartMax;
            if (yl1) yl1.textContent = Math.round(chartMax / 2);
            updateChart(id, diskIOData, chartMax);
          });
        }
      }

      // GPU
      if (!data.gpu) return;
      var gu = document.getElementById('gpu-util');
      var quickGpu = document.getElementById('quick-gpu');
      var quickGpuSub = document.getElementById('quick-gpu-sub');
      var gt = document.getElementById('gpu-temp');
      var gvu = document.getElementById('gpu-vram-used');
      var gvt = document.getElementById('gpu-vram-total');
      var gvp = document.getElementById('gpu-vram-pct');
      var gb = document.getElementById('gpu-bar');
      var gf = document.getElementById('gpu-fan');
      var gfs = document.getElementById('gpu-fan-speed');
      var vramPct = data.gpu.memoryTotal > 0
        ? Math.round((data.gpu.memoryUsed / data.gpu.memoryTotal) * 100)
        : 0;
      if (gu) gu.textContent = data.gpu.utilization + '%';
      if (quickGpu) quickGpu.textContent = data.gpu.utilization + '%';
      if (quickGpuSub) quickGpuSub.textContent = data.gpu.temperature + '°C';
      if (gt) gt.textContent = data.gpu.temperature;
      if (gvu) gvu.textContent = data.gpu.memoryUsed;
      if (gvt) { gvt.textContent = data.gpu.memoryTotal; gpuTotal = Math.round(data.gpu.memoryTotal / 1024); }
      if (gvp) gvp.textContent = vramPct + '%';
      if (gb) gb.style.width = vramPct + '%';
      if (gf && gfs) {
        if (data.gpu.fanSpeed != null && !isNaN(data.gpu.fanSpeed)) {
          gf.classList.remove('hidden');
          gfs.textContent = data.gpu.fanSpeed;
        } else {
          gf.classList.add('hidden');
        }
      }
      var vramGb = data.gpu.memoryTotal > 0 ? +(data.gpu.memoryUsed / 1024).toFixed(1) : 0;
      var gy0 = document.getElementById('gpu-yl-0');
      var gy1 = document.getElementById('gpu-yl-1');
      if (gy0) gy0.textContent = gpuTotal + 'G';
      if (gy1) gy1.textContent = Math.round(gpuTotal / 2) + 'G';
      pushData(gpuData, vramGb);
      updateChart('gpu-chart', gpuData, gpuTotal || 1);
    } catch (e) {}
  }, true);

  function resolveServiceUrl(rawUrl) {
    try {
      var host = window.location.hostname;
      if (host && host !== 'localhost' && host !== '127.0.0.1') {
        return rawUrl.replace(/^(https?:\/\/)(localhost|127\.0\.0\.1)(:\d+)?/i, '$1' + host + '$3');
      }
    } catch (e) {}
    return rawUrl;
  }

  window.filterServices = function(query) {
    var q = (query || '').trim().toLowerCase();
    var cards = document.querySelectorAll('[data-service-card]');
    for (var i = 0; i < cards.length; i++) {
      var hay = cards[i].getAttribute('data-service-search') || '';
      cards[i].style.display = (!q || hay.indexOf(q) !== -1) ? '' : 'none';
    }
  };

  window.checkServices = function(services) {
    var onlineCount = 0;
    var countEl = document.getElementById('services-online-count');
    if (countEl) countEl.textContent = '0';

    // Rewrite service card hrefs if accessed from LAN IP (e.g. mobile phone)
    var cards = document.querySelectorAll('[data-service-card]');
    for (var i = 0; i < cards.length; i++) {
      var raw = cards[i].getAttribute('data-service-url');
      if (raw) cards[i].setAttribute('href', resolveServiceUrl(raw));
    }

    services.forEach(function(svc) {
      var safeId = svc.name.replace(/\s+/g, '-');
      var dot = document.getElementById('status-' + safeId);
      var label = document.getElementById('status-label-' + safeId);
      if (!dot) return;
      var targetUrl = resolveServiceUrl(svc.url);
      fetch(targetUrl, { mode: 'no-cors' })
        .then(function() {
          onlineCount++;
          if (countEl) countEl.textContent = String(onlineCount);
          dot.className = 'w-2.5 h-2.5 rounded-full bg-success ring-4 ring-success/20 transition-all';
          dot.title = 'Online';
          if (label) {
            label.textContent = 'online';
            label.className = 'text-success uppercase tracking-wider text-[10px] font-semibold';
          }
        })
        .catch(function() {
          dot.className = 'w-2.5 h-2.5 rounded-full bg-error ring-4 ring-error/20 transition-all';
          dot.title = 'Offline';
          if (label) {
            label.textContent = 'offline';
            label.className = 'text-error uppercase tracking-wider text-[10px] font-semibold';
          }
        });
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
