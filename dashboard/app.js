/* Vantage dashboard — vanilla JS against the FastAPI API. No frameworks. */
(function () {
  "use strict";

  var API = "";
  var pollTimer = null;
  var currentScanId = null;
  var currentSeverity = "all";

  function $(id) { return document.getElementById(id); }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  /* ---------- theme ---------- */
  function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    $("theme-btn").textContent = theme === "dark" ? "Light" : "Dark";
    try { localStorage.setItem("vantage-theme", theme); } catch (e) {}
  }
  (function initTheme() {
    var saved = null;
    try { saved = localStorage.getItem("vantage-theme"); } catch (e) {}
    setTheme(saved || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"));
  })();
  $("theme-btn").addEventListener("click", function () {
    setTheme(document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark");
  });

  /* ---------- views ---------- */
  function showView(name) {
    ["home", "detail", "new"].forEach(function (v) {
      $("view-" + v).hidden = v !== name;
    });
    window.scrollTo(0, 0);
  }
  $("new-scan-btn").addEventListener("click", function () { showView("new"); });
  $("back-btn").addEventListener("click", function () { showView("home"); loadHome(); });
  $("back-btn-2").addEventListener("click", function () { showView("home"); loadHome(); });

  /* ---------- badges (word first, colour never alone) ---------- */
  function sevBadge(sev) {
    var tone = sev === "critical" || sev === "high" ? "red"
             : sev === "medium" ? "strong" : "neutral";
    return '<span class="badge ' + tone + '"><span class="dot"></span>' + esc(cap(sev)) + "</span>";
  }
  function statusBadge(status) {
    var map = { complete: ["green", "Complete"], queued: ["strong", "Queued"],
                running: ["strong", "Running"], failed: ["red", "Failed"] };
    var m = map[status] || ["neutral", cap(status)];
    return '<span class="badge ' + m[0] + '">' + (m[0] === "green" || m[0] === "red" ? '<span class="dot"></span>' : "") + esc(m[1]) + "</span>";
  }
  function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  function fmtTime(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    return d.toLocaleString(undefined, { month: "short", day: "numeric",
      hour: "numeric", minute: "2-digit" });
  }

  /* ---------- home ---------- */
  function loadHome() {
    fetch(API + "/api/health").then(function (r) {
      $("api-status").textContent = r.ok ? "Connected" : "API unreachable";
    }).catch(function () { $("api-status").textContent = "API unreachable"; });

    fetch(API + "/api/scans").then(function (r) { return r.json(); }).then(function (scans) {
      var list = $("scan-list");
      list.innerHTML = "";
      $("scan-empty").hidden = scans.length > 0;
      scans.forEach(function (s) {
        var b = document.createElement("button");
        b.className = "row"; b.setAttribute("role", "listitem");
        b.innerHTML =
          '<div class="row-main"><div class="row-title">' + esc(s.target_host) + "</div>" +
          '<div class="row-sub">' + esc(fmtTime(s.started_at)) + " · scan " + s.id + "</div></div>" +
          statusBadge(s.status) + '<span class="chev">›</span>';
        b.addEventListener("click", function () { openScan(s.id); });
        list.appendChild(b);
      });
      var done = scans.filter(function (s) { return s.status === "complete"; });
      if (done.length) {
        fetch(API + "/api/scans/" + done[0].id + "/summary").then(function (r) { return r.json(); })
          .then(function (sum) {
            var c = sum.severity_counts || {};
            ["critical", "high", "medium", "low", "info"].forEach(function (sev) {
              $("count-" + sev).textContent = c[sev] || 0;
            });
          }).catch(function () {});
      }
    }).catch(function () {
      $("scan-empty").hidden = false;
      $("scan-empty").textContent = "Could not reach the API. Is the server running?";
    });
  }

  /* ---------- scan detail ---------- */
  var SEV_FILTER = { all: "info", high: "high", medium: "medium", low: "low", info: "info" };

  function openScan(id) {
    currentScanId = id;
    currentSeverity = "all";
    document.querySelectorAll("#severity-filter .seg-btn").forEach(function (btn) {
      var on = btn.dataset.sev === "all";
      btn.classList.toggle("active", on);
      btn.setAttribute("aria-checked", on ? "true" : "false");
    });
    showView("detail");
    loadDetail();
  }

  function loadDetail() {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    fetch(API + "/api/scans/" + currentScanId).then(function (r) { return r.json(); })
      .then(function (s) {
        $("detail-target").textContent = s.target_host;
        $("detail-meta").textContent =
          (s.status === "complete" ? "Finished " : s.status === "failed" ? "Failed " : "Started ") +
          fmtTime(s.started_at || s.finished_at) +
          (s.error ? " · " + s.error : "");
        if (s.status === "queued" || s.status === "running") {
          pollTimer = setInterval(loadDetail, 2000);
        }
        loadFindings();
      });
  }

  function loadFindings() {
    fetch(API + "/api/scans/" + currentScanId + "/findings?min_severity=" + SEV_FILTER[currentSeverity])
      .then(function (r) { return r.json(); }).then(function (findings) {
        var list = $("finding-list");
        list.innerHTML = "";
        $("finding-empty").hidden = findings.length > 0;
        findings.forEach(function (f) {
          var b = document.createElement("button");
          b.className = "row"; b.setAttribute("role", "listitem");
          var where = esc(f.target) + (f.port ? ":" + f.port : "");
          b.innerHTML =
            '<div class="row-main"><div class="row-title">' + esc(f.title) + "</div>" +
            '<div class="row-sub">' + where + "</div></div>" +
            sevBadge(f.severity) + '<span class="chev">›</span>';
          var detail = document.createElement("div");
          detail.className = "finding-detail"; detail.hidden = true;
          detail.innerHTML =
            "<h4>Description</h4><p>" + esc(f.description) + "</p>" +
            (f.evidence ? "<h4>Evidence</h4><div class='mono-block'>" + esc(f.evidence) + "</div>" : "") +
            (f.recommendation ? "<h4>Recommendation</h4><p>" + esc(f.recommendation) + "</p>" : "") +
            '<p class="conf-note">Confidence: ' + esc(f.confidence) +
            (f.confidence === "heuristic" ? " — verify before acting." : " — directly observed.") + "</p>";
          b.addEventListener("click", function () {
            detail.hidden = !detail.hidden;
            b.querySelector(".chev").textContent = detail.hidden ? "›" : "‹";
          });
          list.appendChild(b);
          list.appendChild(detail);
        });
      });
  }

  document.querySelectorAll("#severity-filter .seg-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      currentSeverity = btn.dataset.sev;
      document.querySelectorAll("#severity-filter .seg-btn").forEach(function (other) {
        var on = other === btn;
        other.classList.toggle("active", on);
        other.setAttribute("aria-checked", on ? "true" : "false");
      });
      loadFindings();
    });
    btn.addEventListener("keydown", function (e) {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      var btns = Array.prototype.slice.call(document.querySelectorAll("#severity-filter .seg-btn"));
      var i = btns.indexOf(btn) + (e.key === "ArrowRight" ? 1 : -1);
      i = (i + btns.length) % btns.length;
      btns[i].focus(); btns[i].click();
      e.preventDefault();
    });
  });

  /* ---------- new scan ---------- */
  function setError(id, message) {
    var el = $(id);
    if (!message) { el.hidden = true; el.textContent = ""; return; }
    el.hidden = false; el.textContent = message;
  }

  $("scan-form").addEventListener("submit", function (e) {
    e.preventDefault();
    ["target-error", "scope-error", "auth-error", "form-error"].forEach(function (id) { setError(id, null); });
    $("target-input").removeAttribute("aria-invalid");

    var target = $("target-input").value.trim();
    if (!target) {
      $("target-input").setAttribute("aria-invalid", "true");
      setError("target-error", "Add the target hostname or IP, like 127.0.0.1.");
      return;
    }
    var file = $("scope-input").files[0];
    if (!file) {
      setError("scope-error", "Choose the signed scope YAML that names this target.");
      return;
    }
    if (!$("auth-check").checked) {
      setError("auth-error", "Confirm you hold written authorization before scanning.");
      return;
    }

    var reader = new FileReader();
    reader.onload = function () {
      var ports = $("ports-input").value.split(",").map(function (p) { return parseInt(p.trim(), 10); })
        .filter(function (p) { return p > 0 && p < 65536; });
      var body = {
        host: target,
        scope_yaml: String(reader.result),
        authorized: true,
        ports: ports.length ? ports : null
      };
      var btn = $("run-btn");
      btn.disabled = true; btn.textContent = "Starting…";
      fetch(API + "/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      }).then(function (r) {
        return r.json().then(function (data) { return { status: r.status, data: data }; });
      }).then(function (res) {
        btn.disabled = false; btn.textContent = "Run scan";
        if (res.status === 202) {
          openScan(res.data.scan_id);
        } else if (res.status === 403) {
          setError("form-error", "The scope file is not signed. Complete the authorization block (signed_by, signed_date, statement) and try again.");
        } else if (res.status === 400) {
          setError("form-error", "That target is outside the signed scope. Check the scope file names this exact target.");
        } else if (res.status === 422) {
          setError("form-error", "The scope file could not be read as YAML. Compare it with scope.example.yaml.");
        } else {
          setError("form-error", "Something went wrong starting the scan. Check the API is running and try again.");
        }
      }).catch(function () {
        btn.disabled = false; btn.textContent = "Run scan";
        setError("form-error", "Could not reach the API. Start the server and try again.");
      });
    };
    reader.readAsText(file);
  });

  loadHome();
})();
