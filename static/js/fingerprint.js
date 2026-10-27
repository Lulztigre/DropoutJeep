(function () {
  'use strict';

  function stableHash(str) {
    var hash = 0;
    if (!str) return hash;
    for (var i = 0; i < str.length; i++) {
      var chr = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + chr;
      hash |= 0;
    }
    return hash;
  }

  function getCanvasHash() {
    try {
      var canvas = document.createElement('canvas');
      var ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillText('DJ fingerprint', 2, 2);
      ctx.fillStyle = '#E11D48';
      ctx.fillRect(2, 18, 40, 10);
      return stableHash(canvas.toDataURL('image/png'));
    } catch (e) {
      return null;
    }
  }

  function getWebglHash() {
    try {
      var canvas = document.createElement('canvas');
      var gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return null;
      var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      return stableHash(
        (debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : '') +
        (debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : '')
      );
    } catch (e) {
      return null;
    }
  }

  function getBatteryLevel() {
    if (navigator.getBattery) {
      return navigator.getBattery().then(function (b) { return b.level; });
    }
    return Promise.resolve(null);
  }

  function listenForMouse(callback) {
    var count = 0;
    function handler() {
      count++;
      if (count >= 3) {
        callback(count);
        document.removeEventListener('mousemove', handler);
        document.removeEventListener('mousedown', handler);
      }
    }
    document.addEventListener('mousemove', handler);
    document.addEventListener('mousedown', handler);
    setTimeout(function () {
      document.removeEventListener('mousemove', handler);
      document.removeEventListener('mousedown', handler);
      callback(count);
    }, 2500);
  }

  window.collectFingerprint = function (endpoint) {
    var data = {
      ua: navigator.userAgent,
      language: navigator.language,
      languages: navigator.languages ? navigator.languages.slice(0, 5) : [],
      platform: navigator.platform,
      screen: {
        width: screen.width,
        height: screen.height,
        colorDepth: screen.colorDepth,
        pixelRatio: window.devicePixelRatio
      },
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      touch: 'ontouchstart' in window || navigator.maxTouchPoints > 0,
      cores: navigator.hardwareConcurrency || null,
      memory: navigator.deviceMemory || null,
      canvas_hash: getCanvasHash(),
      webgl_hash: getWebglHash(),
      plugins: Array.from(navigator.plugins || []).slice(0, 5).map(function (p) {
        return { name: p.name, filename: p.filename };
      }),
      referrer: document.referrer || null,
      mouse_events: 0,
      battery_level: null
    };

    function send() {
      try {
        fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        }).catch(function () {});
      } catch (e) {}
    }

    listenForMouse(function (count) {
      data.mouse_events = count;
      getBatteryLevel().then(function (level) {
        data.battery_level = level;
        send();
      }).catch(send);
    });
  };
})();
