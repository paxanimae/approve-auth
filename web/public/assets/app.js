// Progressive enhancement only -- every page this file touches keeps
// working with JavaScript disabled (spec section 2/5): the waiting page's
// own <meta http-equiv="refresh"> and manual "Refresh" link are the
// fallback, and this script's only job is to replace that dumb fixed-
// interval reload with the actual polling schedule spec section 5 step 5
// describes, without a full-page flash on every tick.
(function () {
  "use strict";

  var STATUS_URL = "/__manual-approval/status";
  var TEN_MINUTES_MS = 10 * 60 * 1000;

  function currentState() {
    return document.body.getAttribute("data-state") || "";
  }

  function removeMetaRefresh() {
    var meta = document.querySelector('meta[http-equiv="refresh" i]');
    if (meta && meta.parentNode) meta.parentNode.removeChild(meta);
  }

  function setReconnecting(isReconnecting) {
    var notice = document.getElementById("reconnecting-notice");
    if (notice) notice.hidden = !isReconnecting;
  }

  // jitter(5000, 1000) means 4500-5500ms -- spec: "every five seconds
  // with jitter."
  function jitter(baseMs, spreadMs) {
    return baseMs + Math.floor(Math.random() * spreadMs) - Math.floor(spreadMs / 2);
  }

  function createPoller() {
    var startedAt = Date.now();
    var consecutiveFailures = 0;
    var timer = null;
    var fetchInFlight = false;

    function nextDelayMs() {
      if (consecutiveFailures > 0) return 60000; // spec: "back off to 60 seconds" on failure
      if (Date.now() - startedAt < TEN_MINUTES_MS) return jitter(5000, 1000);
      return 15000; // spec: "every 15 seconds after ten minutes"
    }

    function scheduleNext() {
      if (document.hidden) return; // spec: "Pause polling in hidden tabs"
      timer = setTimeout(tick, nextDelayMs());
    }

    function tick() {
      timer = null;
      if (document.hidden || fetchInFlight) return;
      fetchInFlight = true;

      fetch(STATUS_URL, { headers: { Accept: "application/json" }, credentials: "same-origin" })
        .then(function (res) {
          if (!res.ok) throw new Error("status endpoint returned " + res.status);
          return res.json();
        })
        .then(function (data) {
          consecutiveFailures = 0;
          fetchInFlight = false;
          setReconnecting(false);
          // Reload to get the fully server-rendered page for the new
          // state, rather than re-implementing every state's markup
          // here too -- this still avoids the fixed dumb reload the
          // no-JS meta-refresh does, since it only reloads on an actual
          // change instead of every tick.
          if (data && typeof data.state === "string" && data.state !== currentState()) {
            location.reload();
            return;
          }
          scheduleNext();
        })
        .catch(function () {
          fetchInFlight = false;
          consecutiveFailures++;
          setReconnecting(true);
          scheduleNext();
        });
    }

    function resumeIfDue() {
      if (!document.hidden && !timer && !fetchInFlight) tick();
    }

    return { start: scheduleNext, resumeIfDue: resumeIfDue };
  }

  if (document.body && document.body.hasAttribute("data-state")) {
    removeMetaRefresh();
    var poller = createPoller();
    poller.start();
    document.addEventListener("visibilitychange", poller.resumeIfDue);
  }
})();
