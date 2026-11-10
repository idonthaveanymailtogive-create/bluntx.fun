// Frame-buster: frame-ancestors cannot be set from a meta tag on GitHub Pages.
if (window.top !== window.self) {
  document.documentElement.classList.add('framed');
  try { window.top.location = window.self.location.href; } catch (e) {}
}
