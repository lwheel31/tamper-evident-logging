# Local presentation shell

This deck displays exported slide images around the existing, separately running
TamperLab Streamlit application. The HTML is a shell, not a recreation of the
PowerPoint design. Missing PNGs show obvious placeholder panels.

## Start both servers

From the repository root, install the optional UI extra if needed:

```powershell
python -m pip install -e ".[ui]"
```

In terminal 1, start the existing demo on loopback:

```powershell
python -m streamlit run ui/app.py --server.address 127.0.0.1 --server.port 8501 --server.headless true --browser.gatherUsageStats false
```

In terminal 2, serve only the presentation directory:

```powershell
python -m http.server 8000 --bind 127.0.0.1 --directory presentation
```

Open **http://127.0.0.1:8000/**. The direct demo is
**http://127.0.0.1:8501/**; the iframe uses
**http://127.0.0.1:8501/?embed=true**. Both servers must remain running.
If using a virtual environment, activate it first or use its Python executable.
Serving only `presentation/` keeps the repository's generated runs and private
stores outside the static server's document root.

## Slides and replacement images

| Presentation position | File or experience |
|---|---|
| 1 | `assets/slides/slide-1.png` |
| 2 | `assets/slides/slide-2.png` |
| 3 | `assets/slides/slide-3.png` |
| 4 | Interactive TamperLab iframe; no PNG needed |
| 5 | `assets/slides/slide-5.png` |
| 6 | `assets/slides/slide-6.png` |

Export the final PowerPoint slides as PNGs and place them at exactly those paths
under `presentation/`. Prefer 1920 × 1080 (16:9) exports, or a higher-resolution
16:9 export for scaling. No JavaScript or HTML changes are needed. Refresh the
browser after replacing files; use a hard refresh if an older image is cached.
An image is fitted without cropping or stretching against a dark background.
The 16:9 canvas is centered, and a small reserved bottom rail keeps controls
off the slide content. There are no slide borders or decorative frames.

Images are loaded once per page session. Navigation toggles existing elements,
and the iframe is created on the first visit to position 4 and then retained.
Moving away and back does not reset its URL or deliberately reload Streamlit.
A browser refresh, closing the tab, loss of the Streamlit process, or browser
resource management can still lose state. The shell never restarts the demo.

## Controls

| Key | Action when focus is on the presentation shell |
|---|---|
| Right, Space, PageDown | Next slide |
| Left, PageUp | Previous slide |
| Home / End | First / last slide |
| F | Enter or exit browser fullscreen |
| T | Show or hide the presenter timer |
| S | Start or pause the timer, when its panel is visible |
| R | Reset to 0:00 and pause, when its panel is visible |
| D | Show or hide demo fallback help on slide 4 |

Previous/Next, slide position, fullscreen, and timer controls are in the bottom
rail. They fade after inactivity; moving the mouse over the shell or rail, or
tabbing to controls, reveals them. They do not cover the slide image.
The optional timer is hidden and stopped initially. Showing it does not start
it. Its target is **7:30**, after which the elapsed display changes subtly;
there is no alarm or automatic slide advance. Hiding it does not pause it.
Timer state is local to this page session and resets on a browser refresh.

The browser's usual fullscreen shortcut also works (often F11 on Windows;
browser/platform shortcuts vary). The deck remains usable if the Fullscreen API
is denied. Escape normally exits browser fullscreen rather than advancing slides.

## Live demo, focus, and fallback

The real Streamlit UI fills position 4. Its code, configuration, security headers,
experiment behavior, and private stores are not changed by the shell.
Dropdowns and other form controls keep their normal keyboard behavior. Keys
inside the iframe are handled by Streamlit, not by presentation navigation.
Click **Focus deck**, Previous/Next, or a static slide to restore shell keyboard
focus. Tab navigation also remains available.

**Open Live Demo** is always available in the slide 4 control rail and opens the
original app in a separate tab. Close that tab or switch back to the presentation
to continue. **Demo help** (or D with shell focus) shows those instructions if
the iframe is blank, blocked, or unreliable. A failed local health request opens
the fallback automatically. If Streamlit is stopped, start it separately before
opening the link; use **Show embedded demo** to dismiss the fallback panel.

The shell cannot inspect cross-origin iframe contents. A frame load event or an
opaque health response does not prove that the application rendered. The health
probe detects some connection failures, not every embedding or browser-policy
failure; the manual fallback remains available in all cases. If the embedded
app failed before Streamlit started, opening the standalone demo avoids changing
the existing iframe URL; a deck refresh is another option, but resets page state.
Do not weaken headers or change Streamlit configuration to force embedding.

## Before presenting

- Start Streamlit before opening the deck and keep both terminals open.
- Check the five final PNGs and all six positions at the intended projector size.
- Enter fullscreen and verify the slide image fit and control focus.
- Test the embedded live demo, Run Experiment, selectors, and retained state
  after moving to another slide and returning. Test Open Live Demo as a backup.
- Reset the timer, start it manually when speaking, and aim for about 7:30.
- Keep a local PowerPoint/PDF backup ready. This shell has no CDN, external
  fonts, analytics, or external service dependencies; it works offline once the
  existing local Python environment is installed.

Do not place experiment results, keys, trusted stores, caches, or virtual
environments in `presentation/` or its assets directory.
