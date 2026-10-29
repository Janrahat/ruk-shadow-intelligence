/* RUK SHADOW INTELLIGENCE - dashboard behaviour
 * No framework, no build step: this file is served as-is.
 * Tasks:
 *   1. Draw the 24h traffic sparkline from the data baked into the DOM.
 *   2. Subscribe to the SSE feed and append new events live.
 *   3. Keep the stat cards in sync via the JSON stats endpoint.
 *   4. Copy-to-clipboard for the share URL.
 */
(function () {
  "use strict";

  /* ------------------------------------------------------------------ */
  /* Traffic chart                                                       */
  /* ------------------------------------------------------------------ */
  function drawChart() {
    var host = document.getElementById("traffic-chart");
    if (!host) return;

    var series;
    try {
      series = JSON.parse(host.getAttribute("data-series") || "[]");
    } catch (err) {
      series = [];
    }
    if (!Array.isArray(series) || series.length < 2) {
      host.innerHTML = '<p class="muted small">Not enough data for a chart yet.</p>';
      return;
    }

    var values = series.map(function (pair) {
      return Number(pair[1]) || 0;
    });
    var labels = series.map(function (pair) {
      return String(pair[0]);
    });

    var max = Math.max.apply(null, values.concat([1]));
    var W = 600;
    var H = 148;
    var padY = 12;
    var stepX = W / Math.max(1, values.length - 1);

    var points = values.map(function (value, index) {
      var x = index * stepX;
      var y = H - padY - (value / max) * (H - padY * 2);
      return [x, y];
    });

    var line = points
      .map(function (point, index) {
        return (index === 0 ? "M" : "L") + point[0].toFixed(1) + "," + point[1].toFixed(1);
      })
      .join(" ");

    var area =
      line +
      " L" + W + "," + H +
      " L0," + H + " Z";

    var dots = points
      .filter(function (_, index) { return values[index] > 0; })
      .map(function (point) {
        return '<circle cx="' + point[0].toFixed(1) + '" cy="' + point[1].toFixed(1) +
          '" r="2.6" fill="#f5b544"/>';
      })
      .join("");

    var peak = Math.max.apply(null, values);
    var svg =
      '<svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" ' +
      'role="img" aria-label="Hourly visits, peak ' + peak + '">' +
      '<defs><linearGradient id="rukFill" x1="0" y1="0" x2="0" y2="1">' +
      '<stop offset="0%" stop-color="#22d3ee" stop-opacity="0.34"/>' +
      '<stop offset="100%" stop-color="#22d3ee" stop-opacity="0"/>' +
      "</linearGradient></defs>" +
      '<path d="' + area + '" fill="url(#rukFill)"/>' +
      '<path d="' + line + '" fill="none" stroke="#22d3ee" stroke-width="1.8" ' +
      'stroke-linejoin="round" stroke-linecap="round"/>' +
      dots +
      "</svg>" +
      '<div class="chart-axis">' +
      '<span>' + labels[0].slice(11) + "</span>" +
      '<span>peak ' + peak + "</span>" +
      '<span>' + labels[labels.length - 1].slice(11) + "</span>" +
      "</div>";

    host.innerHTML = svg;
  }

  /* ------------------------------------------------------------------ */
  /* Live feed                                                           */
  /* ------------------------------------------------------------------ */
  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function rowFor(payload) {
    var article = document.createElement("article");
    article.className = "feed-row is-new";

    var parts = [
      { tag: "time", text: payload.time },
      { tag: "span", cls: "tag", text: payload.campaign || "no campaign" },
      { tag: "span", text: payload.location || "-" },
      { tag: "span", text: payload.browser || "unknown" },
      {
        tag: "span",
        cls: "chip chip-" + (payload.device || "unknown"),
        text: payload.device || "unknown"
      }
    ];

    parts.forEach(function (part) {
      var element = document.createElement(part.tag);
      if (part.cls) element.className = part.cls;
      element.textContent = part.text;
      article.appendChild(element);
    });

    setTimeout(function () {
      article.classList.remove("is-new");
    }, 2600);

    return article;
  }

  function startFeed() {
    var feed = document.getElementById("feed");
    if (!feed || typeof window.EventSource === "undefined") return;

    var streamUrl = feed.getAttribute("data-stream");
    if (!streamUrl) return;

    var pill = document.getElementById("live-pill");
    var pillText = document.getElementById("live-text");

    var lastId = 0;
    feed.querySelectorAll("[data-event-id]").forEach(function (node) {
      lastId = Math.max(lastId, Number(node.getAttribute("data-event-id")) || 0);
    });

    function setState(state, text) {
      if (pill) {
        pill.classList.remove("is-live", "is-down");
        if (state) pill.classList.add(state);
      }
      if (pillText) pillText.textContent = text;
    }

    var source = new EventSource(streamUrl);

    source.addEventListener("ready", function () {
      setState("is-live", "live");
    });

    source.addEventListener("event", function (message) {
      var payload;
      try {
        payload = JSON.parse(message.data);
      } catch (err) {
        return;
      }

      var empty = document.getElementById("feed-empty");
      if (empty) empty.remove();

      feed.insertBefore(rowFor(payload), feed.firstChild);

      while (feed.children.length > 40) {
        feed.removeChild(feed.lastChild);
      }

      bumpTotals();
    });

    source.addEventListener("error", function () {
      setState("is-down", "reconnecting");
    });

    source.onopen = function () {
      setState("is-live", "live");
    };
  }

  /* ------------------------------------------------------------------ */
  /* Stat cards                                                          */
  /* ------------------------------------------------------------------ */
  function bumpTotals() {
    var url = document.body.getAttribute("data-stats-url");
    if (!url) return;

    fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" })
      .then(function (response) {
        return response.ok ? response.json() : null;
      })
      .then(function (data) {
        if (!data) return;
        setText("stat-total", data.total_events);
        setText("stat-unique", data.unique_events);
        setText("stat-links", data.active_links);
        setText("stat-campaigns", data.campaigns);
      })
      .catch(function () {
        /* A failed refresh is not worth interrupting the operator for. */
      });
  }

  function setText(id, value) {
    var node = document.getElementById(id);
    if (node && value != null) node.textContent = value;
  }

  /* ------------------------------------------------------------------ */
  /* Copy to clipboard                                                   */
  /* ------------------------------------------------------------------ */
  function wireCopyButtons() {
    document.querySelectorAll("[data-copy]").forEach(function (button) {
      button.addEventListener("click", function () {
        var target = document.getElementById(button.getAttribute("data-copy"));
        if (!target) return;
        var text = target.textContent.trim();
        var original = button.textContent;

        function done(ok) {
          button.textContent = ok ? "Copied" : "Press Ctrl+C";
          setTimeout(function () {
            button.textContent = original;
          }, 1600);
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(
            function () { done(true); },
            function () { done(false); }
          );
        } else {
          var range = document.createRange();
          range.selectNodeContents(target);
          var selection = window.getSelection();
          selection.removeAllRanges();
          selection.addRange(range);
          done(true);
        }
      });
    });
  }

  /* ------------------------------------------------------------------ */
  document.addEventListener("DOMContentLoaded", function () {
    drawChart();
    startFeed();
    wireCopyButtons();
  });
})();
