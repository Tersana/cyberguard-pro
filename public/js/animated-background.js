/**
 * animated-background.js
 * Renders 80 slowly floating dots on a full-screen transparent canvas.
 * Shared across login, signup, forgot-password, reset-password,
 * email-verification, and verify-email pages.
 */
(function () {
    'use strict';

    var NUM_DOTS = 80;
    var dots = [];

    // --- helpers --------------------------------------------------------
    function randVelocity() {
        var v = 0;
        while (Math.abs(v) < 0.1) v = Math.random() * 0.8 - 0.4;
        return v;
    }

    function makeDot(w, h) {
        return {
            x:       Math.random() * w,
            y:       Math.random() * h,
            r:       Math.random() * 1.5 + 1,
            vx:      randVelocity(),
            vy:      randVelocity(),
            opacity: Math.random() * 0.3 + 0.2
        };
    }

    // --- canvas ---------------------------------------------------------
    var canvas = document.createElement('canvas');
    canvas.id = 'animDotsCanvas';
    canvas.style.cssText =
        'position:fixed;top:0;left:0;width:100%;height:100%;' +
        'z-index:15;pointer-events:none;';

    var ctx = canvas.getContext('2d');

    function resize() {
        canvas.width  = window.innerWidth;
        canvas.height = window.innerHeight;
        dots = [];
        for (var i = 0; i < NUM_DOTS; i++) dots.push(makeDot(canvas.width, canvas.height));
    }

    function frame() {
        var w = canvas.width, h = canvas.height;
        ctx.clearRect(0, 0, w, h);

        for (var i = 0; i < dots.length; i++) {
            var d = dots[i];
            d.x += d.vx;
            d.y += d.vy;

            if (d.x < -d.r)  d.x = w + d.r;
            else if (d.x > w + d.r) d.x = -d.r;
            if (d.y < -d.r)  d.y = h + d.r;
            else if (d.y > h + d.r) d.y = -d.r;

            ctx.beginPath();
            ctx.arc(d.x, d.y, d.r, 0, 6.2832);
            ctx.fillStyle = 'rgba(255,255,255,' + d.opacity + ')';
            ctx.fill();
        }
        requestAnimationFrame(frame);
    }

    // --- boot -----------------------------------------------------------
    function boot() {
        document.body.insertBefore(canvas, document.body.firstChild);
        resize();
        window.addEventListener('resize', resize);
        frame();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
