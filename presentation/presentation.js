"use strict";

(() => {
  const deck = document.querySelector("#deck");
  const slides = [...deck.querySelectorAll(".slide")];
  const previous = document.querySelector("#previous");
  const next = document.querySelector("#next");
  const position = document.querySelector("#position");
  const rail = document.querySelector("#control-rail");
  const frame = document.querySelector("#demo-frame");
  const demoControls = document.querySelector("#demo-controls");
  const fallback = document.querySelector("#demo-fallback");
  const demoHelp = document.querySelector("#demo-help");
  const timerPanel = document.querySelector("#timer-panel");
  const elapsed = document.querySelector("#elapsed");
  const startButton = document.querySelector("#timer-start");
  const timerToggle = document.querySelector("#toggle-timer");
  const fullscreenButton = document.querySelector("#fullscreen");
  const status = document.querySelector("#shell-status");
  const demoURL = "http://127.0.0.1:8501";
  const targetMs = 7.5 * 60 * 1000;
  let current = 0;
  let hideControlsTimeout;
  let demoStarted = false;
  let accumulatedMs = 0;
  let timerStartedAt = null;

  // Each image is assigned once. Navigating only toggles existing sections;
  // neither slide images nor the demo iframe are rebuilt on slide changes.
  for (const image of deck.querySelectorAll(".slide-image")) {
    const placeholder = image.previousElementSibling;
    image.addEventListener("load", () => {
      if (image.naturalWidth > 0) {
        placeholder.hidden = true;
        image.hidden = false;
      }
    });
    image.addEventListener("error", () => {
      image.hidden = true;
      placeholder.hidden = false;
    });
    image.src = image.dataset.src;
  }

  function focusDeck() {
    deck.focus({ preventScroll: true });
  }

  function revealControls() {
    document.body.dataset.controlsVisible = "true";
    window.clearTimeout(hideControlsTimeout);
    hideControlsTimeout = window.setTimeout(() => {
      if (!rail.contains(document.activeElement) && !rail.matches(":hover")) {
        document.body.dataset.controlsVisible = "false";
      }
    }, 2800);
  }

  function showFallback(show, message) {
    fallback.hidden = !show;
    demoHelp.setAttribute("aria-expanded", String(show));
    if (message) document.querySelector("#fallback-message").textContent = message;
    if (show) {
      revealControls();
      fallback.querySelector("a").focus({ preventScroll: true });
    }
  }

  function startDemoOnce() {
    if (demoStarted) return;
    demoStarted = true;
    frame.src = `${demoURL}/?embed=true`;
    // An opaque health response only indicates reachability, not successful
    // embedding. Cross-origin iframe.onload is not proof of app rendering.
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 5000);
    fetch(`${demoURL}/_stcore/health`, {
      mode: "no-cors", cache: "no-store", signal: controller.signal,
    }).catch(() => {
      showFallback(true, "The local demo could not be reached. Start Streamlit, then use Open Live Demo. Close that tab or switch back here to continue.");
    }).finally(() => window.clearTimeout(timeout));
  }

  function goTo(index) {
    current = Math.max(0, Math.min(slides.length - 1, index));
    slides.forEach((slide, i) => { slide.hidden = i !== current; });
    position.textContent = `${current + 1} / ${slides.length}`;
    previous.disabled = current === 0;
    next.disabled = current === slides.length - 1;
    demoControls.hidden = current !== 3;
    deck.setAttribute("aria-label", slides[current].getAttribute("aria-label"));
    history.replaceState(null, "", `#${current + 1}`);
    focusDeck();
    revealControls();
    if (current === 3) startDemoOnce();
  }

  function elapsedMs() {
    return accumulatedMs + (timerStartedAt === null ? 0 : performance.now() - timerStartedAt);
  }

  function paintTimer() {
    const milliseconds = elapsedMs();
    const seconds = Math.floor(milliseconds / 1000);
    elapsed.textContent = `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, "0")}`;
    timerPanel.dataset.targetReached = String(milliseconds >= targetMs);
  }

  function toggleTimer() {
    timerPanel.hidden = !timerPanel.hidden;
    timerToggle.setAttribute("aria-expanded", String(!timerPanel.hidden));
    paintTimer();
    revealControls();
  }

  function startOrPauseTimer() {
    if (timerStartedAt === null) {
      timerStartedAt = performance.now();
      startButton.textContent = "Pause";
    } else {
      accumulatedMs = elapsedMs();
      timerStartedAt = null;
      startButton.textContent = "Start";
    }
    paintTimer();
    revealControls();
  }

  function resetTimer() {
    accumulatedMs = 0;
    timerStartedAt = null;
    startButton.textContent = "Start";
    paintTimer();
    revealControls();
  }

  async function toggleFullscreen() {
    try {
      if (document.fullscreenElement) await document.exitFullscreen();
      else if (document.documentElement.requestFullscreen) await document.documentElement.requestFullscreen();
      else throw new Error("Fullscreen unavailable");
    } catch {
      status.textContent = "Fullscreen unavailable. Use the browser's standard fullscreen shortcut, or continue in this window.";
      fullscreenButton.title = status.textContent;
    }
    revealControls();
  }

  function interactiveFocus(event) {
    return document.activeElement === frame || event.target instanceof Element &&
      Boolean(event.target.closest("input, select, textarea, button, a, [contenteditable]:not([contenteditable='false']), [role='combobox'], [role='textbox'], [role='slider']"));
  }

  document.addEventListener("keydown", (event) => {
    if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey || interactiveFocus(event)) return;
    switch (event.key) {
      case "ArrowRight": case " ": case "PageDown":
        event.preventDefault(); goTo(current + 1); break;
      case "ArrowLeft": case "PageUp":
        event.preventDefault(); goTo(current - 1); break;
      case "Home": event.preventDefault(); goTo(0); break;
      case "End": event.preventDefault(); goTo(slides.length - 1); break;
      case "f": case "F": event.preventDefault(); void toggleFullscreen(); break;
      case "t": case "T": event.preventDefault(); toggleTimer(); break;
      case "s": case "S":
        if (!timerPanel.hidden) { event.preventDefault(); startOrPauseTimer(); }
        break;
      case "r": case "R":
        if (!timerPanel.hidden) { event.preventDefault(); resetTimer(); }
        break;
      case "d": case "D":
        if (current === 3) { event.preventDefault(); showFallback(fallback.hidden); }
        break;
    }
  });

  previous.addEventListener("click", () => goTo(current - 1));
  next.addEventListener("click", () => goTo(current + 1));
  document.querySelector("#focus-deck").addEventListener("click", focusDeck);
  demoHelp.addEventListener("click", () => showFallback(fallback.hidden));
  document.querySelector("#dismiss-fallback").addEventListener("click", () => { showFallback(false); focusDeck(); });
  timerToggle.addEventListener("click", toggleTimer);
  startButton.addEventListener("click", startOrPauseTimer);
  document.querySelector("#timer-reset").addEventListener("click", resetTimer);
  fullscreenButton.addEventListener("click", () => { void toggleFullscreen(); });
  deck.addEventListener("pointerdown", (event) => { if (event.target === deck || event.target.closest(".image-canvas")) focusDeck(); });
  document.addEventListener("pointermove", revealControls, { passive: true });
  document.addEventListener("touchstart", revealControls, { passive: true });
  document.addEventListener("focusin", revealControls);
  document.addEventListener("fullscreenchange", () => {
    fullscreenButton.textContent = document.fullscreenElement ? "Exit fullscreen" : "Fullscreen";
  });
  window.setInterval(() => { if (timerStartedAt !== null) paintTimer(); }, 250);

  const requested = /^#[1-6]$/.test(location.hash) ? Number(location.hash.slice(1)) - 1 : 0;
  goTo(requested);
})();
