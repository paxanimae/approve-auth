// Progressive enhancement only -- every page this file touches keeps
// working with JavaScript disabled (spec section 2/5). Two independent
// enhancements live here:
//
//   1. The request page auto-submits itself a few seconds after load
//      instead of waiting for a click on "Request access", so an
//      unattended browser (e.g. a reception TV) needs no interaction
//      beyond the initial navigation. The label/message fields and the
//      button stay fully visible and usable the entire time: typing in
//      either field cancels the automatic submission so a human who's
//      actually present can fill them in and submit manually, and the
//      countdown text says so.
//
//   2. The waiting page replaces the no-JS "Continue" / "Open
//      application" button-clicks with the same sequence driven
//      automatically: claim, verify the new session, acknowledge, and
//      navigate straight to the protected app. It also replaces the
//      dumb fixed-interval <meta http-equiv="refresh"> reload with the
//      actual polling schedule spec section 5 step 5 describes, without
//      a full-page flash on every tick.
(function () {
  "use strict";

  var STATUS_URL = "/__approve-auth/status";
  var CLAIM_URL = "/__approve-auth/claim";
  var SESSION_URL = "/__approve-auth/session";
  var ACK_URL = "/__approve-auth/ack";
  var WAITING_URL = "/__approve-auth/waiting";
  var TEN_MINUTES_MS = 10 * 60 * 1000;
  var AUTO_SUBMIT_DELAY_S = 6;

  function postJSON(url, body) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body || {}),
    }).then(function (res) {
      if (!res.ok) throw new Error(url + " returned " + res.status);
      return res.json();
    });
  }

  function getJSON(url) {
    return fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (body) {
        return { ok: res.ok, body: body };
      });
    });
  }

  // --- Request page: delayed auto-submit, cancelable by typing ---

  function initRequestPage() {
    var form = document.getElementById("request-form");
    if (!form) return false;

    var notice = document.getElementById("auto-notice");
    var csrfField = form.querySelector('[name="csrf_token"]');
    var returnToField = form.querySelector('[name="return_to"]');
    var labelField = form.querySelector('[name="label"]');
    var messageField = form.querySelector('[name="message"]');

    var remaining = AUTO_SUBMIT_DELAY_S;
    var timer = null;
    var canceled = false;
    var submitted = false;

    function setNotice(text) {
      if (notice) notice.textContent = text;
    }

    function cancelAuto() {
      if (canceled || submitted) return;
      canceled = true;
      if (timer) clearTimeout(timer);
      setNotice("");
    }

    function doSubmit() {
      if (submitted) return;
      submitted = true;
      if (timer) clearTimeout(timer);
      setNotice("Requesting access…");

      postJSON(form.getAttribute("action"), {
        csrf_token: csrfField ? csrfField.value : "",
        return_to: returnToField ? returnToField.value : "",
        label: labelField ? labelField.value : "",
        message: messageField ? messageField.value : "",
      })
        .then(function () {
          location.href = WAITING_URL;
        })
        .catch(function () {
          // Leave the visible form usable -- a human present can still
          // submit it manually, and an unattended browser will pick
          // this up again on its next navigation/retry.
          submitted = false;
          setNotice("");
        });
    }

    function tick() {
      if (canceled || submitted) return;
      if (remaining <= 0) {
        doSubmit();
        return;
      }
      var hint = labelField || messageField ? " start typing to fill in a message first." : "";
      setNotice("Requesting access automatically in " + remaining + "s…" + hint);
      remaining--;
      timer = setTimeout(tick, 1000);
    }

    if (labelField) labelField.addEventListener("input", cancelAuto);
    if (messageField) messageField.addEventListener("input", cancelAuto);
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      cancelAuto();
      doSubmit();
    });

    tick();
    return true;
  }

  // --- Waiting page: auto-advance past approved/claimed ---

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

  function finishWithAck(fallbackReturnTo) {
    return postJSON(ACK_URL, {})
      .then(function (ackData) {
        location.href = (ackData && ackData.return_to) || fallbackReturnTo || "/";
      });
  }

  // autoAdvance drives spec section 5 step 7 (claim -> verify /session ->
  // ack -> navigate) without waiting for the no-JS "Continue"/"Open
  // application" clicks. Returns true if it took over (caller should not
  // also reload/reschedule), false if this state has no automatic step.
  var advancing = false;
  function autoAdvance(state, csrfToken) {
    if (advancing) return true;

    if (state === "approved" && csrfToken) {
      advancing = true;
      postJSON(CLAIM_URL, { csrf_token: csrfToken })
        .then(function (claimData) {
          return getJSON(SESSION_URL).then(function (session) {
            if (!session.ok || !session.body || !session.body.active) {
              location.reload();
              return;
            }
            return finishWithAck(claimData.return_to);
          });
        })
        .catch(function () {
          advancing = false;
          location.reload();
        });
      return true;
    }

    if (state === "claimed") {
      advancing = true;
      getJSON(SESSION_URL)
        .then(function (session) {
          if (!session.ok || !session.body || !session.body.active) {
            // Matches the no-JS "Almost there, please refresh" case --
            // the access cookie isn't visible on this request yet.
            advancing = false;
            location.reload();
            return;
          }
          return finishWithAck();
        })
        .catch(function () {
          advancing = false;
          location.reload();
        });
      return true;
    }

    return false;
  }

  function createPoller() {
    var startedAt = Date.now();
    var consecutiveFailures = 0;
    var timer = null;
    var fetchInFlight = false;

    // jitter(5000, 1000) means 4500-5500ms -- spec: "every five seconds
    // with jitter."
    function jitter(baseMs, spreadMs) {
      return baseMs + Math.floor(Math.random() * spreadMs) - Math.floor(spreadMs / 2);
    }

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
          if (data && typeof data.state === "string" && data.state !== currentState()) {
            if (autoAdvance(data.state, data.csrf_token)) return;
            // No automatic step for this state (denied/canceled/timed
            // out/pending) -- fall back to the fully server-rendered
            // page rather than re-implementing every state's markup
            // here too.
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

  function initWaitingPage() {
    if (!document.body || !document.body.hasAttribute("data-state")) return false;

    var initialCSRF = document.body.getAttribute("data-csrf-token") || "";
    if (autoAdvance(currentState(), initialCSRF)) return true;

    removeMetaRefresh();
    var poller = createPoller();
    poller.start();
    document.addEventListener("visibilitychange", poller.resumeIfDue);
    return true;
  }

  if (!initRequestPage()) initWaitingPage();
})();
