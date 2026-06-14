(function() {
  var MAX_POINTS = 60;
  var cpuData = [];
  var ramData = [];
  var gpuData = [];
  var ramTotal = 0;
  var gpuTotal = 0;

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

  var CX0 = 22, CX1 = 143, CY0 = 3, CY1 = 40;
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

  function setAxisLabels(id, max, unit) {
    var vals = [max, Math.round(max / 2), 0];
    for (var i = 0; i < 3; i++) {
      var el = document.getElementById(id + '-yl-' + i);
      if (el) el.textContent = vals[i] + (i < 2 && unit ? unit : '');
    }
  }

  document.addEventListener('htmx:beforeSwap', function() {
    cpuData = [];
    ramData = [];
    gpuData = [];
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
      pushData(cpuData, data.cpu.average);
      setAxisLabels('cpu-chart', 100, '%');
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
      pushData(ramData, data.ram.used);
      setAxisLabels('ram-chart', Math.round(ramTotal), 'GB');
      updateChart('ram-chart', ramData, ramTotal);

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
      pushData(gpuData, vramGb);
      setAxisLabels('gpu-chart', gpuTotal, 'GB');
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
