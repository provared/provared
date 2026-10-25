// The first script of the "try it" page, an ordinary one, so that it runs
// even where the page's module cannot be loaded. If the module has not
// readied the button within 15 seconds, or one of its scripts fails to load,
// the visitor is told so, in place of "Please wait". The module clears the
// message once it is ready, so a slow load that ends well says nothing false.
(function () {
  function stuck() {
    var run = document.getElementById('run');
    var status = document.getElementById('status');
    if (!run || !status || !run.disabled || run.getAttribute('data-ready') === 'yes') return;
    run.textContent = 'Not available';
    status.textContent = 'This page could not start in this browser. Nothing was sent anywhere. Use the checking page, linked below, or the command-line checker.';
  }
  window.addEventListener('error', function (event) {
    if (event.target && event.target.tagName === 'SCRIPT') setTimeout(stuck, 0);
  }, true);
  setTimeout(stuck, 15000);
})();
