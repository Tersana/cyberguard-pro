/**
 * echo-config.js — Laravel Echo + Reverb configuration
 *
 * Vanilla JS (no bundler). Requires these script tags (loaded before this file):
 *   <script src="lib/pusher.min.js"></script>
 *   <script src="lib/echo.iife.js"></script>
 *
 * The echo.iife.js build sets window.Echo = { default: EchoClass, ... }.
 * Pusher reads window.Pusher automatically.
 *
 * Credentials are read from window.APP_CONFIG (set in a per-environment
 * config.js that is gitignored), falling back to current known values.
 */
(function () {
  "use strict";

  // Guard: libraries must be loaded first
  if (
    typeof window.Echo !== "object" ||
    typeof window.Echo.default !== "function"
  ) {
    console.error(
      "[echo-config] laravel-echo IIFE not loaded. " +
        "Ensure lib/echo.iife.js is included before echo-config.js."
    );
    return;
  }

  if (typeof window.Pusher === "undefined") {
    console.error(
      "[echo-config] pusher-js not loaded. " +
        "Ensure lib/pusher.min.js is included before echo-config.js."
    );
    return;
  }

  var cfg = window.APP_CONFIG || {};
  var REVERB_KEY    = cfg.REVERB_APP_KEY || "p77kyuc5noyjaqc0t2te";
  var REVERB_HOST   = cfg.REVERB_HOST    || "peptonelike-lelia-interdepartmentally.ngrok-free.dev";
  var REVERB_PORT   = Number(cfg.REVERB_PORT || 443);
  var REVERB_SCHEME = cfg.REVERB_SCHEME  || "https";

  try {
    window.echoInstance = new window.Echo.default({
      broadcaster:       "reverb",
      key:               REVERB_KEY,
      wsHost:            REVERB_HOST,
      wsPort:            REVERB_PORT,
      wssPort:           REVERB_PORT,
      forceTLS:          REVERB_SCHEME === "https",
      enabledTransports: ["ws", "wss"],
    });

    console.log(
      "[Echo] Instance created — host:",
      REVERB_HOST,
      "port:",
      REVERB_PORT,
      "tls:",
      REVERB_SCHEME === "https"
    );
  } catch (err) {
    console.error("[Echo] Failed to create Echo instance:", err);
  }
})();
