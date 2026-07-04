(function () {
  var root = document.documentElement;
  var saved = localStorage.getItem('reconTheme');
  var prefersLight = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches;
  var initial = saved || (prefersLight ? 'light' : 'dark');
  root.setAttribute('data-theme', initial);

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('themeToggle');
    if (!btn) return;
    btn.addEventListener('click', function () {
      var current = root.getAttribute('data-theme');
      var next = current === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      localStorage.setItem('reconTheme', next);
    });
  });
})();
