(function() {
  var html = document.documentElement;
  var sunIcon = document.getElementById('theme-icon-sun');
  var moonIcon = document.getElementById('theme-icon-moon');

  var savedTheme = sessionStorage.getItem('basho-theme');
  if (savedTheme) {
    html.setAttribute('data-theme', savedTheme);
    updateIcons(savedTheme);
  }

  window.toggleTheme = function() {
    var current = html.getAttribute('data-theme');
    var next = current === 'dracula' ? 'bumblebee' : 'dracula';
    html.setAttribute('data-theme', next);
    sessionStorage.setItem('basho-theme', next);
    updateIcons(next);
  };

  function updateIcons(theme) {
    if (theme === 'dracula') {
      sunIcon.classList.remove('hidden');
      moonIcon.classList.add('hidden');
    } else {
      sunIcon.classList.add('hidden');
      moonIcon.classList.remove('hidden');
    }
  }

  function ensureCoreBars(count) {
    var container = document.getElementById('cpu-core-bars');
    var existing = container.children.length;
    if (existing === count) return;
    container.innerHTML = '';
    for (var i = 0; i < count; i++) {
      var wrapper = document.createElement('div');
      wrapper.className = 'flex items-center gap-2 text-xs';
      wrapper.innerHTML =
        '<span class="w-8 text-right text-base-content/40 shrink-0">c' + i + '</span>' +
        '<div class="flex-1 h-2 bg-base-300 rounded-full overflow-hidden">' +
          '<div id="cpu-core-' + i + '" class="h-full bg-accent rounded-full transition-all duration-500" style="width:0%"></div>' +
        '</div>' +
        '<span id="cpu-core-label-' + i + '" class="w-10 text-right text-base-content/60 shrink-0">0%</span>';
      container.appendChild(wrapper);
    }
  }

  document.addEventListener('htmx:sseBeforeMessage', function(evt) {
    evt.preventDefault();
    try {
      var data = JSON.parse(evt.detail.data);
      if (data.type === 'system') {
        var avg = document.getElementById('cpu-average');
        var count = document.getElementById('cpu-count');
        if (avg) avg.textContent = data.cpu.average + '%';
        if (count) count.textContent = data.cpu.count + ' logical';
        ensureCoreBars(data.cpu.count);
        data.cpu.cores.forEach(function(core, i) {
          var bar = document.getElementById('cpu-core-' + i);
          var label = document.getElementById('cpu-core-label-' + i);
          if (bar) bar.style.width = core.usage + '%';
          if (label) label.textContent = core.usage + '%';
        });
        var rp = document.getElementById('ram-percent');
        var ru = document.getElementById('ram-used');
        var rt = document.getElementById('ram-total');
        var rc = document.getElementById('ram-cached');
        var rb = document.getElementById('ram-bar');
        if (rp) rp.textContent = data.ram.percent + '%';
        if (ru) ru.textContent = data.ram.used;
        if (rt) rt.textContent = data.ram.total;
        if (rc) rc.textContent = data.ram.cached;
        if (rb) rb.style.width = data.ram.percent + '%';
        if (data.gpu) {
          var gu = document.getElementById('gpu-util');
          var gt = document.getElementById('gpu-temp');
          var gvu = document.getElementById('gpu-vram-used');
          var gvt = document.getElementById('gpu-vram-total');
          var gb = document.getElementById('gpu-bar');
          var vramPct = data.gpu.memoryTotal > 0
            ? Math.round((data.gpu.memoryUsed / data.gpu.memoryTotal) * 100)
            : 0;
          if (gu) gu.textContent = data.gpu.utilization + '%';
          if (gt) gt.textContent = data.gpu.temperature;
          if (gvu) gvu.textContent = data.gpu.memoryUsed;
          if (gvt) gvt.textContent = data.gpu.memoryTotal;
          if (gb) gb.style.width = vramPct + '%';
        }
      }
    } catch(e) {}
  }, true);

  window.checkServices = function(services) {
    services.forEach(function(svc) {
      var id = 'status-' + svc.name.replace(/\s+/g, '-');
      var dot = document.getElementById(id);
      if (!dot) return;
      fetch(svc.url, { mode: 'no-cors' })
        .then(function() {
          dot.className = 'w-3.5 h-3.5 rounded-full bg-success shadow-lg shadow-success/50';
          dot.title = 'Online';
        })
        .catch(function() {
          dot.className = 'w-3.5 h-3.5 rounded-full bg-error shadow-lg shadow-error/50';
          dot.title = 'Offline';
        });
    });
  };
})();
