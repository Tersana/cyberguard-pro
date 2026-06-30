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
    var jwtToken = localStorage.getItem("cyberguard_jwt");
    var activeOrgId = localStorage.getItem("cyberguard_active_org_id");

    window.echoInstance = new window.Echo.default({
      broadcaster:       "reverb",
      key:               REVERB_KEY,
      wsHost:            REVERB_HOST,
      wsPort:            REVERB_PORT,
      wssPort:           REVERB_PORT,
      forceTLS:          REVERB_SCHEME === "https",
      enabledTransports: ["ws", "wss"],
      authEndpoint:      REVERB_SCHEME + "://" + REVERB_HOST + "/api/broadcasting/auth",
      auth: {
        headers: {
          Authorization: jwtToken ? "Bearer " + jwtToken : "",
          "X-Organization-Id": activeOrgId || "",
          "ngrok-skip-browser-warning": "true"
        }
      }
    });

    console.log(
      "[Echo] Instance created — host:",
      REVERB_HOST,
      "port:",
      REVERB_PORT,
      "tls:",
      REVERB_SCHEME === "https"
    );

    // Global background user notifications subscription state
    var userNotificationChannel = null;

    var subscribeToUserNotifications = function () {
      if (userNotificationChannel) return; // Already subscribed

      var userRaw = localStorage.getItem("cyberguard_user");
      if (!userRaw || !window.echoInstance) return;

      try {
        var user = JSON.parse(userRaw);
        if (user && user.id) {
          console.log("[Echo] Subscribing to notifications for user ID:", user.id);
          userNotificationChannel = window.echoInstance.private("user." + user.id);
          userNotificationChannel.listen('.notification', function (event) {
            console.log("[Echo] Received background notification:", event);
            if (window.CyberNotify && event.message) {
              window.CyberNotify.alert(event.message, { type: event.type || 'info' });
            }
          });
        }
      } catch (e) {
        console.warn("[Echo] Error establishing user notifications channel:", e);
      }
    };

    var unsubscribeFromUserNotifications = function () {
      if (userNotificationChannel && window.echoInstance) {
        var userRaw = localStorage.getItem("cyberguard_user");
        if (userRaw) {
          try {
            var user = JSON.parse(userRaw);
            if (user && user.id) {
              console.log("[Echo] Leaving notifications channel for user ID:", user.id);
              window.echoInstance.leave("user." + user.id);
            }
          } catch (_) {}
        }
        userNotificationChannel = null;
      }
    };

    // Global background organization settings subscription state
    var orgChannel = null;

    var subscribeToOrgEvents = function () {
      if (orgChannel) {
        var oldOrgId = orgChannel.name.replace("private-organization.", "");
        console.log("[Echo] Leaving old org channel:", oldOrgId);
        window.echoInstance.leave("organization." + oldOrgId);
        orgChannel = null;
      }

      var activeOrgId = localStorage.getItem("cyberguard_active_org_id");
      if (!activeOrgId || !window.echoInstance) return;

      console.log("[Echo] Subscribing to org channel: private-organization." + activeOrgId);
      try {
        orgChannel = window.echoInstance.private("organization." + activeOrgId);

        var refreshEvents = [
          '.member.added',
          '.member.updated',
          '.member.removed',
          '.invitation.created',
          '.invitation.accepted',
          '.invitation.cancelled'
        ];

        refreshEvents.forEach(function (evt) {
          orgChannel.listen(evt, function (data) {
            console.log("[Echo] Org event received:", evt, data);
            
            // Reload settings pane if open on organization tab
            if (window.SettingsPanel && window.SettingsPanel.isOpen && window.SettingsPanel.activeTabId === 'org-settings') {
              if (window.OrganizationSettings && typeof window.OrganizationSettings.loadSettingsPane === 'function') {
                window.OrganizationSettings.loadSettingsPane();
              }
            }

            // Show a notification alert if data contains a message
            if (window.CyberNotify && data && data.message) {
              window.CyberNotify.alert(data.message, { type: 'info' });
            }
          });
        });
      } catch (e) {
        console.warn("[Echo] Error establishing organization channel:", e);
      }
    };

    var unsubscribeFromOrgEvents = function () {
      if (orgChannel && window.echoInstance) {
        var activeOrgId = localStorage.getItem("cyberguard_active_org_id");
        if (activeOrgId) {
          console.log("[Echo] Leaving org channel:", activeOrgId);
          window.echoInstance.leave("organization." + activeOrgId);
        }
        orgChannel = null;
      }
    };

    // Initialize subscriptions immediately if session exists
    subscribeToUserNotifications();
    subscribeToOrgEvents();

    // Listen to session changes
    window.addEventListener("userLoggedIn", function () {
      console.log("[Echo] userLoggedIn event, establishing WebSocket auth headers & subscriptions");
      var token = localStorage.getItem("cyberguard_jwt");
      if (window.echoInstance && window.echoInstance.options && window.echoInstance.options.auth) {
        window.echoInstance.options.auth.headers.Authorization = token ? "Bearer " + token : "";
      }
      subscribeToUserNotifications();
      subscribeToOrgEvents();
    });

    window.addEventListener("userLoggedOut", function () {
      console.log("[Echo] userLoggedOut event, clearing WebSocket subscriptions");
      unsubscribeFromUserNotifications();
      unsubscribeFromOrgEvents();
    });

    // Listen to workspace context changes to update X-Organization-Id dynamically
    document.addEventListener("cyberguard:orgContextChanged", function (event) {
      var newOrgId = event.detail?.organizationId || localStorage.getItem("cyberguard_active_org_id") || "";
      if (window.echoInstance && window.echoInstance.options && window.echoInstance.options.auth) {
        window.echoInstance.options.auth.headers['X-Organization-Id'] = newOrgId;
        console.log("[Echo] Dynamic active organization header updated to:", newOrgId);
      }
      // Re-establish organization subscription channel dynamically
      subscribeToOrgEvents();
    });

  } catch (err) {
    console.error("[Echo] Failed to create Echo instance:", err);
  }
})();
