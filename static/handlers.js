(function() {
  var MAX_POINTS = 60;
  var cpuData = [];
  var ramData = [];
  var gpuData = [];
  var ramTotal = 0;
  var gpuTotal = 0;
  var diskIOData = [];
  var diskIOMax = 1;

  function init() {
    var html = document.documentElement;
    var sunIcon = document.getElementById('theme-icon-sun');
    var moonIcon = document.getElementById('theme-icon-moon');

    var savedTheme = sessionStorage.getItem('basho-theme');
    if (savedTheme) {
      html.setAttribute('data-theme', savedTheme);
      if (sunIcon && moonIcon) updateIcons(savedTheme, sunIcon, moonIcon);
    }

    window.toggleTheme = function() {
      var current = html.getAttribute('data-theme');
      var next = current === 'dracula' ? 'bumblebee' : 'dracula';
      html.setAttribute('data-theme', next);
      sessionStorage.setItem('basho-theme', next);
      if (sunIcon && moonIcon) updateIcons(next, sunIcon, moonIcon);
    };

    window.toggleSidebar = function() {
      var s = document.getElementById('sidebar');
      if (s) s.classList.toggle('collapsed');
    };
  }

  function updateIcons(theme, sun, moon) {
    if (theme === 'dracula') {
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

  var CX0 = 14, CX1 = 135, CY0 = 3, CY1 = 40;
  var CW = CX1 - CX0, CH = CY1 - CY0;

  function svgPath(data, max) {
    if (data.length < 2) return '';
    var parts = [];
    for (var i = 0; i < data.length; i++) {
      var x = CX0 + (i / (data.length - 1)) * CW;
      var y = CY1 - (data[i] / max) * CH;
      parts.push((i === 0 ? 'M' : 'L') + x.toFixed(1) + ' ' + y.toFixed(1));
    }
    return parts.join('');
  }

  function svgFillPath(data, max) {
    if (data.length < 2) return '';
    return svgPath(data, max) + ' L' + CX1.toFixed(1) + ' ' + CY1 + ' L' + CX0.toFixed(1) + ' ' + CY1 + ' Z';
  }

  function updateChart(id, data, max) {
    var line = document.getElementById(id + '-line');
    var fill = document.getElementById(id + '-fill');
    if (line) line.setAttribute('d', svgPath(data, max));
    if (fill) fill.setAttribute('d', svgFillPath(data, max));
  }

  function createDiskId(device) {
    return 'disk-' + device.replace(/[^a-zA-Z0-9]/g, '_');
  }

  function createDiskCard(id, disk) {
    var container = document.getElementById('disks-container');
    if (!container) return null;
    var card = document.createElement('div');
    card.className = 'card bg-base-200/60 backdrop-blur-sm border border-base-300/50 shadow-xl';
    card.id = id;
    card.innerHTML =
      '<div class="card-body">' +
        '<div class="flex items-center gap-2 mb-2">' +
          '<div class="w-3 h-3 rounded-full bg-info animate-pulse"></div>' +
          '<h2 class="card-title text-lg truncate">' + (disk.name || disk.device) + '</h2>' +
        '</div>' +
        '<div id="' + id + '-info">' +
          '<div class="text-4xl font-bold text-info" id="' + id + '-percent">' + disk.usePercent + '%</div>' +
          '<div class="text-sm text-base-content/60 mt-1">' +
            '<span id="' + id + '-used">' + disk.used + '</span> GB / <span id="' + id + '-size">' + disk.totalSize + '</span> GB' +
          '</div>' +
          '<div class="h-3 bg-base-300 rounded-full mt-2 overflow-hidden">' +
            '<div id="' + id + '-bar" class="h-full bg-info rounded-full transition-all duration-500" style="width: ' + disk.usePercent + '%"></div>' +
          '</div>' +
        '</div>' +
        '<div class="mt-auto pt-3">' +
          '<svg class="w-full h-24" id="' + id + '-chart" viewBox="0 0 137 45" preserveAspectRatio="none">' +
            '<defs>' +
              '<linearGradient id="' + id + '-grad" x1="0" y1="0" x2="0" y2="1">' +
                '<stop offset="0%" stop-color="var(--color-info)" stop-opacity="0.3"></stop>' +
                '<stop offset="100%" stop-color="var(--color-info)" stop-opacity="0.02"></stop>' +
              '</linearGradient>' +
            '</defs>' +
            '<line x1="14" y1="3" x2="14" y2="40" stroke="var(--color-base-content)" stroke-opacity="0.12" stroke-width="1"></line>' +
            '<line x1="14" y1="21.5" x2="135" y2="21.5" stroke="var(--color-base-content)" stroke-opacity="0.08" stroke-width="0.5" stroke-dasharray="2,2"></line>' +
            '<line x1="14" y1="40" x2="135" y2="40" stroke="var(--color-base-content)" stroke-opacity="0.12" stroke-width="0.5"></line>' +
            '<text id="' + id + '-yl0" x="12" y="6" text-anchor="end" fill="var(--color-base-content)" fill-opacity="0.25" font-size="3.5" font-family="monospace">0</text>' +
            '<text id="' + id + '-yl1" x="12" y="24.5" text-anchor="end" fill="var(--color-base-content)" fill-opacity="0.25" font-size="3.5" font-family="monospace">0</text>' +
            '<text id="' + id + '-yl2" x="12" y="43" text-anchor="end" fill="var(--color-base-content)" fill-opacity="0.25" font-size="3.5" font-family="monospace">0</text>' +
            '<path id="' + id + '-fill" fill="url(#' + id + '-grad)" d=""></path>' +
            '<path id="' + id + '-line" fill="none" stroke="var(--color-info)" stroke-width="1.5" d=""></path>' +
          '</svg>' +
        '</div>' +
      '</div>';
    container.appendChild(card);
    return card;
  }

  document.addEventListener('htmx:beforeSwap', function() {
    cpuData = [];
    ramData = [];
    gpuData = [];
    diskIOData = [];
    diskIOMax = 1;
    ramTotal = 0;
    gpuTotal = 0;
  });

  document.addEventListener('htmx:sseBeforeMessage', function(evt) {
    evt.preventDefault();
    try {
      var data = JSON.parse(evt.detail.data);
      if (data.type !== 'system') return;

      var avg = document.getElementById('cpu-average');
      var count = document.getElementById('cpu-count');
      var cbar = document.getElementById('cpu-bar');
      if (avg) avg.textContent = data.cpu.average + '%';
      if (count) count.textContent = data.cpu.count + ' logical';
      if (cbar) cbar.style.width = data.cpu.average + '%';
      var cy0 = document.getElementById('cpu-yl-0');
      var cy1 = document.getElementById('cpu-yl-1');
      if (cy0) cy0.textContent = '100%';
      if (cy1) cy1.textContent = '50%';
      pushData(cpuData, data.cpu.average);
      updateChart('cpu-chart', cpuData, 100);

      var rp = document.getElementById('ram-percent');
      var ru = document.getElementById('ram-used');
      var rt = document.getElementById('ram-total');
      var rc = document.getElementById('ram-cached');
      var rb = document.getElementById('ram-bar');
      if (rp) rp.textContent = data.ram.percent + '%';
      if (ru) ru.textContent = data.ram.used;
      if (rt) { rt.textContent = data.ram.total; ramTotal = data.ram.total; }
      if (rc) rc.textContent = data.ram.cached;
      if (rb) rb.style.width = data.ram.percent + '%';
      var ry0 = document.getElementById('ram-yl-0');
      var ry1 = document.getElementById('ram-yl-1');
      if (ry0) ry0.textContent = Math.round(ramTotal) + 'GB';
      if (ry1) ry1.textContent = Math.round(ramTotal / 2) + 'GB';
      pushData(ramData, data.ram.used);
      updateChart('ram-chart', ramData, ramTotal);

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
        pushData(diskIOData, data.diskIO.totalIO_sec);
        if (data.diskIO.totalIO_sec > diskIOMax) diskIOMax = data.diskIO.totalIO_sec;
        var chartMax = Math.ceil(diskIOMax * 1.2) || 1;
        data.disks.forEach(function(disk) {
          var id = createDiskId(disk.device);
          var yl0 = document.getElementById(id + '-yl0');
          var yl1 = document.getElementById(id + '-yl1');
          if (yl0) yl0.textContent = chartMax;
          if (yl1) yl1.textContent = Math.round(chartMax / 2);
          updateChart(id, diskIOData, chartMax);
        });
      }

      if (!data.gpu) return;
      var gu = document.getElementById('gpu-util');
      var gt = document.getElementById('gpu-temp');
      var gvu = document.getElementById('gpu-vram-used');
      var gvt = document.getElementById('gpu-vram-total');
      var gb = document.getElementById('gpu-bar');
      var gf = document.getElementById('gpu-fan');
      var gfs = document.getElementById('gpu-fan-speed');
      var vramPct = data.gpu.memoryTotal > 0
        ? Math.round((data.gpu.memoryUsed / data.gpu.memoryTotal) * 100)
        : 0;
      if (gu) gu.textContent = data.gpu.utilization + '%';
      if (gt) gt.textContent = data.gpu.temperature;
      if (gvu) gvu.textContent = data.gpu.memoryUsed;
      if (gvt) { gvt.textContent = data.gpu.memoryTotal; gpuTotal = Math.round(data.gpu.memoryTotal / 1024); }
      if (gb) gb.style.width = vramPct + '%';
      if (gf && gfs) {
        if (data.gpu.fanSpeed != null) {
          gf.classList.remove('hidden');
          gfs.textContent = data.gpu.fanSpeed;
        } else {
          gf.classList.add('hidden');
        }
      }
      var vramGb = data.gpu.memoryTotal > 0 ? Math.round(data.gpu.memoryUsed / 1024) : 0;
      var gy0 = document.getElementById('gpu-yl-0');
      var gy1 = document.getElementById('gpu-yl-1');
      if (gy0) gy0.textContent = gpuTotal + 'GB';
      if (gy1) gy1.textContent = Math.round(gpuTotal / 2) + 'GB';
      pushData(gpuData, vramGb);
      updateChart('gpu-chart', gpuData, gpuTotal);
    } catch(e) {}
  }, true);

  window.checkServices = function(services) {
    services.forEach(function(svc) {
      var id = 'status-' + svc.name.replace(/\s+/g, '-');
      var dot = document.getElementById(id);
      if (!dot) return;
      fetch(svc.url, { mode: 'no-cors' })
        .then(function() {
          dot.className = 'w-3 h-3 rounded-full bg-success absolute top-3 right-3 ring-2 ring-base-100';
          dot.title = 'Online';
        })
        .catch(function() {
          dot.className = 'w-3 h-3 rounded-full bg-error absolute top-3 right-3 ring-2 ring-base-100';
          dot.title = 'Offline';
        });
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
