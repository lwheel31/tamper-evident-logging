"""Presentation-only dashboard. Launch: streamlit run ui/app.py

Install the optional extra first: python -m pip install -e ".[ui]"
The existing runner performs every logging, attack, and verification operation.
"""

from __future__ import annotations

from collections import Counter
from html import escape
import json
from pathlib import Path

import streamlit as st

from tamperlog import experiment
from presentation import (
    ALLOWED_SOURCE_FILES, ATTACKS, MODES, OUTCOMES, OUTPUT_DIR,
    evidence, interpretation, record_window, result_row, source_choices, source_excerpt,
)

st.set_page_config(page_title="Tamper-Evident Logging", page_icon="◈", layout="wide")
st.html("<style>" + Path(__file__).with_name("style.css").read_text(encoding="utf-8") + "</style>")


def h(value: object) -> str:
    return escape(str(value), quote=True)


def status_style(outcome: str) -> str:
    return OUTCOMES.get(outcome, ("unavailable", ""))[0]


def empty_state() -> None:
    st.html('<div class="empty-state"><strong>Start with real evidence.</strong>'
            'Select <b>Run Experiment</b> to generate the logs, apply all four attacks, '
            'and run the existing verifiers.</div>')


def overview(report: dict | None) -> None:
    st.subheader("Four mechanisms. One storage attacker.")
    for (mode, (title, description)), col in zip(MODES.items(), st.columns(4)):
        with col:
            st.html(f'<div class="mode-card"><div class="mode-letter">MODE {mode}</div>'
                    f'<h3>{h(title)}</h3><p>{h(description)}</p></div>')
    st.html('<div class="story"><div><span>01</span> GENERATE</div><div>→</div>'
            '<div><span>02</span> TAMPER</div><div>→</div><div><span>03</span> VERIFY</div>'
            '<div>→</div><div><span>04</span> COMPARE</div></div>')
    left, right = st.columns(2)
    with left, st.container(border=True):
        st.markdown("### Attacker can")
        st.markdown("Read stored logs · modify · delete · reorder · truncate · rewrite attacker-controlled storage.")
    with right, st.container(border=True):
        st.markdown("### Attacker cannot")
        st.markdown("Access HMAC keys · modify trusted checkpoints · control logger or verifier code.")
    st.caption("Trusted stores require independent protection. A separate folder alone does not establish that boundary. "
               "The model assumes no attacker action between a record write and its checkpoint.")
    if report:
        counts = Counter(row["outcome"] for row in report["results"])
        a, b, c = st.columns(3)
        a.metric("Actual attack cases", len(report["results"]))
        b.metric("Detected", counts["DETECTED"])
        c.metric("Missed", counts["MISSED"])
        st.caption("Explore Live Attack Demo for the evidence, then Results for the complete comparison.")
    else:
        empty_state()


def evidence_table(window: list[tuple[int, dict]], incident: int, *, mark_focus: bool = False) -> None:
    rows = []
    for position, record in window:
        details = record["details"]
        incident_record = record["event_type"] == "DATA_EXPORT" and details.get("file") == "payroll.db"
        css = "incident-row" if incident_record else "focus-row" if mark_focus and position == incident else ""
        values = (position, record["seq"], record["timestamp"][11:], record["event_type"],
                  details.get("user", "—"), details.get("file", details.get("action", "—")))
        rows.append(f'<tr class="{css}">' + "".join(f"<td>{h(v)}</td>" for v in values) + "</tr>")
    if not rows:
        rows.append('<tr><td colspan="6" class="empty">No records remain in this window.</td></tr>')
    st.html('<table class="evidence"><thead><tr>'
            '<th>ROW</th><th>SEQ</th><th>TIME · UTC</th><th>EVENT</th><th>USER</th><th>RESOURCE</th>'
            '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>')


def verification_card(row: dict) -> None:
    outcome = row["outcome"]
    semantics = OUTCOMES.get(outcome, ("unavailable", "No comparison is available."))[1]
    st.html(f'<div class="result {status_style(outcome)}"><div class="label">EXISTING VERIFIER · RECORDED RESULT</div>'
            f'<div class="outcome">{h(outcome)}</div><p>{h(semantics)}</p></div>')
    result = row.get("verifier_result") or {}
    validity, position, examined = st.columns(3)
    valid = result.get("valid")
    validity.metric("Verifier validity", "True" if valid is True else "False" if valid is False else "Unavailable")
    bad = row.get("first_bad_seq")
    position.metric("First bad sequence", str(bad) if bad is not None else "—")
    examined.metric("Records examined", result.get("total_records", "—"))
    st.caption(row.get("explanation", "No explanation recorded."))
    steps = row.get("steps", [])
    st.markdown("**Actual transformation:** " + (" → ".join(f"`{step}`" for step in steps) if steps else "Not executed"))
    control = row.get("control_result") or {}
    if control:
        st.caption(f"Untouched control: valid={control.get('valid')} · {control.get('total_records')} records examined. "
                   "The runner checks this control before attributing a detection to the attack.")


def live_demo(report: dict) -> None:
    st.subheader("Follow the evidence.")
    mode_col, attack_col = st.columns([2, 1])
    with mode_col:
        mode = st.selectbox("Logging mode", list(MODES), format_func=lambda m: f"{m} — {MODES[m][0]}", key="demo_mode")
    with attack_col:
        attack = st.selectbox("Attack", ATTACKS, format_func=str.title, key="demo_attack")
    row = result_row(report, mode, attack)
    incident = report["parameters"]["payroll_export_seq"]
    st.html(f'<div class="incident"><span class="inline-outcome {status_style(row["outcome"])}">'
            f'RECORDED: {h(row["outcome"])}</span>Synthetic incident: an administrator exports <b>payroll.db</b>.'
            f' <small>Original sequence <b>{h(incident)}</b> · Mode {h(mode)} · {h(attack.title())}</small></div>')
    st.html('<div class="story"><div><span>01</span> ORIGINAL</div><div>→</div>'
            '<div><span>02</span> STORAGE ATTACK</div><div>→</div><div><span>03</span> VERIFICATION</div></div>')
    if not row.get("attack_applied"):
        st.info("No completed attack is recorded for this case. Review its prerequisite or error result below.")
    else:
        try:
            before, after, relative = evidence(report, row)
        except (OSError, ValueError, KeyError, TypeError):
            st.error("The recorded public artifacts are unavailable or changed. The recorded result below cannot "
                     "describe the currently displayed evidence. Run a fresh experiment to restore the comparison.")
        else:
            before_window = record_window(before, incident)
            after_window = record_window(after, incident, tail=attack == "truncate")
            left, right = st.columns(2)
            with left:
                st.markdown("### Before attack")
                st.caption(f"Original evidence · {len(before)} records · incident highlighted in green")
                evidence_table(before_window, incident)
            with right:
                st.markdown("### After attack")
                st.caption(f"Final attack artifact · {len(after)} records · physical row order preserved")
                evidence_table(after_window, incident, mark_focus=attack == "modify")
            if attack == "modify":
                old = before[incident]["details"].get("file")
                new = after[incident]["details"].get("file")
                st.caption(f"Changed field · details.file: {old} → {new}. The amber row shows the changed record.")
            elif attack == "delete":
                st.caption(f"Record count: {len(before)} → {len(after)}. The incident record was removed; "
                           "any sequence repair is listed in the actual transformation below.")
            elif attack == "reorder":
                st.caption("Compare physical row order and timestamps. Reordering changes chronology; "
                           "it does not remove the export from the log.")
            else:
                end = after[-1]["seq"] if after else "no records"
                st.caption(f"The retained log ends at sequence {end}; original incident sequence {incident}. "
                           "The after panel shows the final retained records.")
            with st.expander("Inspect displayed JSON and public evidence hashes"):
                a, b = st.columns(2)
                with a:
                    st.code(json.dumps([r for _, r in before_window], indent=2), language="json")
                    st.caption("Original SHA-256 · " + report["baselines"][mode]["sha256"])
                with b:
                    st.code(json.dumps([r for _, r in after_window], indent=2), language="json")
                    st.caption("Final artifact SHA-256 · " + row["artifacts"][relative])
    verification_card(row)


def code_view() -> None:
    st.subheader("The code behind the evidence.")
    st.caption("These excerpts are read from the allowlisted repository files at view time. No copied algorithms or editable code.")
    a, b = st.columns([1, 2])
    with a:
        filename = st.selectbox("Source file", ALLOWED_SOURCE_FILES, key="source_file")
    try:
        source, symbols = source_choices(filename)
        options = ["Opening context", *symbols, "Full file"]
        recommended = {"events.py": "Opening context", "loggers.py": "HashChainLogger", "attacks.py": "modify_record",
                       "verifier.py": "_verify", "keyring.py": "rotate_key", "checkpoints.py": "create_checkpoint",
                       "experiment.py": "run_experiment"}[filename]
        with b:
            symbol = st.selectbox("Source excerpt", options, index=options.index(recommended), key="symbol_" + filename)
        excerpt, start = source_excerpt(source, symbol)
    except (OSError, ValueError, SyntaxError):
        st.error("The selected repository source could not be displayed.")
        return
    lines = excerpt.splitlines()
    if len(lines) > 75 and not st.checkbox("Show complete excerpt", key="complete_" + filename):
        excerpt = "\n".join(lines[:75])
        st.caption(f"{filename} · lines {start}–{start + 74} · opening 75 of {len(lines)} selected lines")
    else:
        st.caption(f"{filename} · lines {start}–{start + len(lines) - 1}")
    st.code(excerpt, language="python", line_numbers=True)


def results_view(report: dict) -> None:
    st.subheader("What did verification actually detect?")
    st.caption("Every cell below is read from this run’s report. Unavailable comparisons are never counted as detections.")
    rows = {(row["attack"], row["mode"]): row for row in report["results"]}
    cells = []
    for attack in ATTACKS:
        cell = f"<tr><th>{attack.title()}</th>"
        for mode in MODES:
            outcome = rows[(attack, mode)]["outcome"]
            cell += f'<td class="{status_style(outcome)}">{h(outcome)}</td>'
        cells.append(cell + "</tr>")
    st.html('<table class="matrix"><thead><tr><th>ATTACK</th>'
            + "".join(f"<th>{m} · {h(MODES[m][0])}</th>" for m in MODES)
            + '</tr></thead><tbody>' + "".join(cells) + '</tbody></table>')
    st.markdown("### Untouched baseline verification")
    for (mode, (title, _)), col in zip(MODES.items(), st.columns(4)):
        baseline = report["baselines"][mode]
        verification = baseline.get("verifier_result") or {}
        status = baseline["status"]
        css = "detected" if status == "VALID" else "unavailable"
        with col:
            st.html(f'<div class="baseline"><b>{mode} · {h(title)}</b><span class="badge {css}">{h(status)}</span>'
                    f'<p>Validity: {h(verification.get("valid", "Unavailable"))} · '
                    f'Records: {h(verification.get("total_records", "—"))}</p>'
                    f'<p>{h(baseline["explanation"])}</p></div>')
    st.markdown("### Read this run")
    for note in interpretation(report):
        st.markdown("- " + note)
    with st.expander("Outcome definitions"):
        for outcome, (_, description) in OUTCOMES.items():
            st.markdown(f"**{outcome}** — {description}")
    with st.expander("Public run receipt"):
        st.json({"run": Path(report["run_directory"]).name,
                 "parameters": report["parameters"], "runtime": report["runtime"],
                 "events_sha256": report["events_sha256"], "source_sha256": report["source_sha256"]})


with st.sidebar:
    st.html('<div class="eyebrow">ITIS 6200 · LIVE DEMONSTRATION</div>')
    st.markdown("## TamperLab")
    section = st.radio("Presentation", ["Overview", "Live Attack Demo", "Code", "Results"], key="section")
    st.divider()
    with st.expander("Experiment Settings"):
        event_count = st.number_input("Event count", min_value=4, max_value=500, value=50, step=1,
                                      help="Presentation limit: 4–500 synthetic events.")
        seed = st.number_input("Seed", value=42, step=1)
    run_clicked = st.button("Run Experiment", type="primary", use_container_width=True, key="run_experiment")
    st.caption("Runs the existing engine once. Navigation and selectors reuse the recorded run.")

if section == "Overview":
    st.html('<div class="eyebrow">SECURITY AUDIT LOGS / A CONTROLLED EXPERIMENT</div>')
    st.title("Tamper-Evident Logging")
    st.html('<div class="subtitle">Comparing log integrity defenses against storage-only tampering</div>')
    st.write("We generate the same synthetic security events under four logging mechanisms, tamper with the stored evidence, "
             "and measure whether verification detects the attack.")
else:
    st.html(f'<div class="compact-title">Tamper-Evident Logging <span>{h(section.upper())}</span></div>')

if run_clicked:
    st.session_state.pop("demo_report", None)
    st.session_state.pop("demo_run_error", None)
    with st.spinner("Generating evidence, applying attacks, and running existing verifiers…"):
        try:
            if any(p.is_symlink() for p in (OUTPUT_DIR, *OUTPUT_DIR.parents)):
                raise ValueError("Output directory must not be a symlink")
            st.session_state["demo_report"] = experiment.run_experiment(
                output_dir=OUTPUT_DIR, event_count=int(event_count), seed=int(seed))
        except Exception:
            # Never expose exception text, tracebacks, private keys, or store paths.
            st.session_state["demo_run_error"] = True

report = st.session_state.get("demo_report")
if st.session_state.get("demo_run_error"):
    st.error("The experiment could not complete. No new result is available. Check the local environment and try again.")
if report:
    params = report["parameters"]
    st.caption(f"RECORDED RUN · {Path(report['run_directory']).name} · {params['event_count']} events · seed {params['seed']} "
               "· fresh run only when Run Experiment is clicked")
else:
    st.caption("NO RUN YET · Defaults: 50 events / seed 42")
st.divider()

if section == "Overview":
    overview(report)
elif section == "Code":
    code_view()
elif not report:
    empty_state()
elif section == "Live Attack Demo":
    live_demo(report)
else:
    results_view(report)

st.caption("ITIS 6200 · Lucas: logging & events · Ashton: keys & checkpoints · Julian: verification, attacks & experiments")
