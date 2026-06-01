function startPolling(scanId, reportUrl) {
  const INTERVAL = 2000;

  const icons = {
    done:    ["bi-check-circle-fill", "module-status-done"],
    running: ["bi-arrow-repeat",      "module-status-running spin"],
    pending: ["bi-circle",            "module-status-pending"],
    skipped: ["bi-dash-circle",       "module-status-pending"],
    error:   ["bi-x-circle-fill",     "module-status-error"],
  };

  function updateUI(data) {
    document.getElementById("progress-bar").style.width = data.progress + "%";
    document.getElementById("progress-pct").textContent = data.progress + "%";
    document.getElementById("current-module").textContent = data.current_module || "Running...";

    for (const [key, st] of Object.entries(data.modules || {})) {
      const row = document.getElementById("mod-" + key);
      if (!row) continue;
      const [icon, cls] = icons[st] || icons.pending;
      const iconEl = row.querySelector("i");
      iconEl.className = "bi " + icon + " " + cls;
      const badge = row.querySelector(".badge");
      badge.textContent = st;
    }
  }

  function showError(message) {
    const spinner = document.getElementById("scan-spinner");
    if (spinner) spinner.classList.add("d-none");
    const errorBox = document.getElementById("error-box");
    if (errorBox) errorBox.classList.remove("d-none");
    const errorMsg = document.getElementById("error-message");
    if (errorMsg) errorMsg.textContent = message || "Unknown error";
    const moduleEl = document.getElementById("current-module");
    if (moduleEl) moduleEl.textContent = "Failed";
  }

  function poll() {
    fetch("/api/scan/" + scanId + "/status")
      .then(r => {
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(data => {
        updateUI(data);
        if (data.status === "done") {
          window.location.href = reportUrl;
        } else if (data.status === "error") {
          showError(data.error || "Scan failed. Check scans/" + scanId + "/error.log");
        } else {
          setTimeout(poll, INTERVAL);
        }
      })
      .catch(err => {
        console.warn("Poll failed:", err);
        setTimeout(poll, INTERVAL * 2);
      });
  }

  setTimeout(poll, INTERVAL);
}
