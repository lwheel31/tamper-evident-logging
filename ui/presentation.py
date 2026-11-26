"""Read-only presentation helpers. No logging, attacks, or verification here."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "experiment-results" / "ui-demo"
SOURCE_DIR = ROOT / "src" / "tamperlog"
ALLOWED_SOURCE_FILES = (
    "events.py", "loggers.py", "attacks.py", "verifier.py",
    "keyring.py", "checkpoints.py", "experiment.py",
)
MODES = {
    "A": ("Plaintext", "Structured logs with no cryptographic integrity. Valid-looking edits can pass verification."),
    "B": ("SHA-256 Chain", "Records are linked with public hashes. An attacker can rebuild the chain."),
    "C": ("HMAC Chain", "A secret key authenticates each record. A storage-only attacker cannot generate replacement HMACs."),
    "D": ("HMAC + Checkpoints", "HMAC plus separately trusted checkpoints detects truncation relative to complete, current trusted history."),
}
ATTACKS = ("modify", "delete", "reorder", "truncate")
OUTCOMES = {
    "DETECTED": ("detected", "The attacked artifact failed verification with a valid untouched control."),
    "MISSED": ("missed", "The attacked artifact passed verification. This transformation was not detected."),
    "BLOCKED": ("unavailable", "A prerequisite prevented this case from running. This is not detection."),
    "CANNOT_VERIFY": ("unavailable", "A trustworthy comparison could not be established. This is not detection."),
    "ERROR": ("error", "Execution or evidence validation failed. This is not detection."),
}


def result_row(report: dict, mode: str, attack: str) -> dict:
    """Select an actual result, never infer it from the mechanism."""
    return next(row for row in report["results"]
                if row["mode"] == mode and row["attack"] == attack)


def public_artifact(report: dict, relative: str) -> Path:
    """Restrict reads to known public log artifacts inside this UI's run root.

    No directory traversal, trusted paths, key files, or symlinks are accepted.
    These checks are UI file-selection guards, not a replacement verifier.
    """
    rel = PurePosixPath(relative.replace("\\", "/"))
    if rel.is_absolute() or any(p in ("..", ".") for p in rel.parts):
        raise ValueError("Unavailable presentation artifact")
    parts = rel.parts
    original = (len(parts) == 3 and parts[0] == "logs"
                and parts[1] in MODES and parts[2] == "original.jsonl")
    attacked = (len(parts) == 4 and parts[0] == "attacks"
                and parts[1] in MODES and parts[2] in ATTACKS
                and parts[3].startswith("input.") and parts[3].endswith(".jsonl"))
    if not (original or attacked):
        raise ValueError("Unavailable presentation artifact")
    run = Path(report["run_directory"])
    if any(p.is_symlink() for p in (run, *run.parents)) or run.resolve().parent != OUTPUT_DIR.resolve():
        raise ValueError("Unavailable presentation run")
    if not run.name.startswith("run-"):
        raise ValueError("Unavailable presentation run")
    path = run
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("Unavailable presentation artifact")
    if not path.resolve().is_relative_to(run.resolve()):
        raise ValueError("Unavailable presentation artifact")
    return path


def evidence(report: dict, row: dict) -> tuple[list[dict], list[dict], str]:
    """Read the baseline and final exported attack copy, without touching stores.

    The existing attack helpers append a filename suffix for each operation.
    Among the runner's recorded public artifacts, the longest suffix chain is
    the final output (including any sequence repair or public rehashing).
    """
    mode, attack = row["mode"], row["attack"]
    baseline = report["baselines"][mode]
    before = public_artifact(report, baseline["artifact"])
    candidates = []
    for relative in row["artifacts"]:
        rel = PurePosixPath(relative.replace("\\", "/"))
        if rel.parts[:3] == ("attacks", mode, attack) and rel.name != "input.jsonl":
            public_artifact(report, relative)  # apply the same allowlist before selection
            candidates.append((len(rel.suffixes), relative))
    candidates.sort(reverse=True)
    if not candidates or (len(candidates) > 1 and candidates[0][0] == candidates[1][0]):
        raise ValueError("Final presentation artifact unavailable")
    relative = candidates[0][1]
    after = public_artifact(report, relative)
    return (read_records(before, baseline["sha256"]),
            read_records(after, row["artifacts"][relative]), relative)


def read_records(path: Path, expected_digest: str) -> list[dict]:
    # Display only. Authenticity and validity come exclusively from the runner.
    raw = path.read_bytes()
    # Match the runner's exported evidence digest, not a record tag or HMAC.
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValueError("Presentation artifact changed since the recorded run")
    return [json.loads(line) for line in raw.decode("utf-8").splitlines()]


def record_window(records: list[dict], incident: int, *, tail: bool = False) -> list[tuple[int, dict]]:
    start = max(0, len(records) - 5) if tail else max(0, incident - 2)
    end = len(records) if tail else incident + 3
    return list(enumerate(records))[start:end]


def source_choices(filename: str) -> tuple[str, list[str]]:
    """Read only allowlisted repository Python source; parse it without executing."""
    if filename not in ALLOWED_SOURCE_FILES:
        raise ValueError("Source file is not allowlisted")
    path = SOURCE_DIR / filename
    if path.is_symlink() or path.resolve().parent != SOURCE_DIR.resolve():
        raise ValueError("Source file unavailable")
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    names = [node.name for node in tree.body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    return source, names


def source_excerpt(source: str, name: str) -> tuple[str, int]:
    """Return a real AST-selected function/class, or a file's opening context."""
    lines = source.splitlines()
    if name == "Opening context":
        return "\n".join(lines[:55]), 1
    if name == "Full file":
        return source, 1
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            return "\n".join(lines[start - 1:node.end_lineno]), start
    raise ValueError("Source excerpt unavailable")


def interpretation(report: dict) -> list[str]:
    observed = {(r["mode"], r["attack"]): r["outcome"] for r in report["results"]}
    notes = []
    if all(observed.get(("A", attack)) == "MISSED" for attack in ATTACKS):
        notes.append("A · All four transformations passed. Plaintext checks structure, not cryptographic integrity; deletion and reorder include sequence repair.")
    if all(observed.get(("B", attack)) == "MISSED" for attack in ATTACKS):
        notes.append("B · All four transformations passed after public chain reconstruction. A consistent SHA-256 chain alone does not authenticate its author.")
    if all(observed.get(("C", attack)) == "DETECTED" for attack in ATTACKS[:3]):
        notes.append("C · Modification, deletion, and reordering were detected while the attacker retained the original HMACs.")
    if observed.get(("C", "truncate")) == "MISSED":
        notes.append("C · The retained prefix verified after truncation. HMAC chaining alone does not establish completeness.")
    if observed.get(("D", "truncate")) == "DETECTED":
        notes.append("D · Truncation was detected relative to the independently selected, complete trusted checkpoint history.")
    unavailable = sum(r["outcome"] in ("BLOCKED", "CANNOT_VERIFY", "ERROR") for r in report["results"])
    if unavailable:
        notes.append(f"{unavailable} cases could not establish a scored comparison. Treat unavailable/error cases separately from detection.")
    return notes or ["Inspect the actual outcomes and baseline explanations below; this run does not support the usual four-mode interpretation."]
