// Compatibility shim for the upstream page. The main Academy loaders provide
// the data; this file intentionally avoids mutating the page when they succeed.
window.TraceAtlasAcademyFallback = window.TraceAtlasAcademyFallback || {
  ready: true,
  source: 'bundled-modules'
};
