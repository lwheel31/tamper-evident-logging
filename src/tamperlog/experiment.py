"""Reproducible mode-by-attack experiments on private, isolated run artifacts.

Production uses the real security-store interfaces, never fallback keys/mocks.
Only controlled, independently checked transformations are scored. A valid
untouched control is required before attacks and after each verification.
Owner: Julian
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import platform
import tempfile

from . import attacks, checkpoints, events, keyring, loggers, verifier

MODES = ("A", "B", "C", "D")
ATTACKS = ("modify", "delete", "reorder", "truncate")


def _write_json(path: Path, value: object) -> None:
    with open(path, "x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
        stream.write("\n")


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _checkpoint_digest(identity: str, store: Path) -> str:
    # Checkpoints contain public tags, not keys. Snapshot values, not references
    # to mutable objects returned by a backend or a test double.
    try:
        snapshot = [asdict(cp) for cp in checkpoints.load_checkpoints(identity, store)]
    except (NotImplementedError, KeyError, OSError, ValueError, TypeError):
        raise RuntimeError("cannot verify: trusted checkpoint snapshot unavailable") from None
    return _digest(json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode())


def _verify(mode: str, path: Path, identity: str, keys: Path, anchors: Path) -> dict:
    if mode == "A":
        result = verifier.verify_plaintext(path)
    elif mode == "B":
        result = verifier.verify_hash_chain(path)
    elif mode == "C":
        result = verifier.verify_hmac_chain(path, keys)
    else:
        result = verifier.verify_hmac_checkpoint(path, keys, anchors, expected_log_id=identity)
    if (not isinstance(result, verifier.VerificationResult) or result.mode != mode
            or type(result.valid) is not bool):
        raise TypeError("unexpected verifier result")
    if result.valid and result.total_records and result.log_id != identity:
        raise ValueError("verified identity differs from trusted experiment configuration")
    return asdict(result)


def _verification_failure(mode: str, exc: Exception) -> str:
    # Do not classify every RuntimeError as unavailable trusted data: unexpected
    # implementation exceptions are ERROR. Never export raw exception text,
    # which could contain key bytes or backend-specific sensitive diagnostics.
    if mode in ("C", "D") and (isinstance(exc, NotImplementedError)
            or isinstance(exc, RuntimeError) and str(exc).startswith("cannot verify:")):
        return "CANNOT_VERIFY"
    return "ERROR"


def _apply(mode: str, name: str, path: Path, target: dict) -> tuple[Path, list[str]]:
    if name == "modify":
        output = attacks.modify_record(path, target["target_seq"], deepcopy(target["new_details"]))
    elif name == "delete":
        output = attacks.delete_record(path, target["target_seq"])
    elif name == "reorder":
        output = attacks.reorder_records(path, target["seq_a"], target["seq_b"])
    else:
        output = attacks.truncate_log(path, target["keep_count"])
    steps = [name]
    if mode == "A" and name in ("delete", "reorder"):
        output = attacks.repair_sequences(output)
        steps.append("repair_sequences")
    elif mode == "B":
        output = attacks.rebuild_hash_chain(output)
        steps.append("rebuild_hash_chain")
    return Path(output), steps


def _check_effect(mode: str, name: str, before: list[dict], after: list[dict], target: dict) -> None:
    expected = deepcopy(before)
    if name == "modify":
        expected[target["target_seq"]]["details"] = deepcopy(target["new_details"])
    elif name == "delete":
        del expected[target["target_seq"]]
    elif name == "reorder":
        a, b = target["seq_a"], target["seq_b"]
        expected[a], expected[b] = expected[b], expected[a]
    else:
        expected = expected[:target["keep_count"]]
    if mode == "B" or (mode == "A" and name in ("delete", "reorder")):
        for seq, record in enumerate(expected):
            record["seq"] = seq
    if mode == "B":
        # The verifier checks reconstructed tags. Here check the independent
        # content/order/sequence expectation, without duplicating hash logic.
        expected = [{k: v for k, v in r.items() if k not in ("tag", "prev_tag")} for r in expected]
        after = [{k: v for k, v in r.items() if k not in ("tag", "prev_tag")} for r in after]
    if after != expected:
        raise ValueError("artifact does not match the requested attack")


def render_matrix(report: dict) -> str:
    """Render observed outcomes only; no expected detection table is encoded."""
    rows = {(r["attack"], r["mode"]): r["outcome"] for r in report["results"]}
    lines = ["# Experiment results", "", "| Attack | A | B | C | D |",
             "|---|---|---|---|---|"]
    for attack in ATTACKS:
        lines.append("| " + " | ".join([attack] + [rows[(attack, mode)] for mode in MODES]) + " |")
    lines += ["", "## Untouched baselines", ""]
    for mode in MODES:
        baseline = report["baselines"][mode]
        lines.append(f"- {mode}: {baseline['status']} — {baseline['explanation']}")
    lines += ["", "Detailed verifier results, targets, stages, and evidence hashes: results.json.",
              "BLOCKED is not detection. Reordering changes chronology; it does not remove the export.",
              "Do not publish trusted/; it may contain secret keys.", ""]
    return "\n".join(lines)


def run_experiment(*, output_dir: Path = Path("experiment-results"),
                   event_count: int = 50, seed: int = 42) -> dict:
    """Run all 16 cells; save results.json and matrix.md in a fresh run directory.

    Existing run directories/files are never reused. Defaults preserve the
    original no-argument call while adding configuration and a returned report.
    Event streams, targets, and strategies are deterministic; real HMAC keys
    must remain randomly generated, so keyed bytes need not match across runs.
    Filesystem/export failures raise; per-mode/case failures are recorded.
    """
    if type(event_count) is not int or event_count < 4 or type(seed) is not int:
        raise ValueError("event_count must be an integer >= 4 and seed an integer (not booleans)")
    stream = list(events.generate_events(event_count, seed))
    targets = [i for i, (_, kind, details) in enumerate(stream)
               if kind == "DATA_EXPORT" and details.get("file") == "payroll.db"]
    if len(stream) != event_count or len(targets) != 1 or targets[0] + 1 >= len(stream):
        raise ValueError("expected exactly one payroll export with a following event")
    incident = targets[0]
    plan = {
        "modify": {"target_seq": incident, "new_details": {**stream[incident][2], "file": "reports/q3.xlsx"}},
        "delete": {"target_seq": incident},
        "reorder": {"seq_a": incident, "seq_b": incident + 1},
        "truncate": {"keep_count": incident},
    }
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="run-", dir=output_dir))  # private directory, mode 0700
    report = {"schema_version": 1, "run_directory": str(run),
              "runtime": {"python": platform.python_version(), "system": platform.system()},
              "source_sha256": {Path(module.__file__).name: _digest(Path(module.__file__).read_bytes())
                                for module in (attacks, checkpoints, events, keyring, loggers, verifier)},
              "parameters": {"event_count": event_count, "seed": seed, "checkpoint_interval": 1,
                             "payroll_export_seq": incident, "attack_targets": plan},
              "events_sha256": None, "baselines": {}, "results": []}
    report["source_sha256"]["experiment.py"] = _digest(Path(__file__).read_bytes())
    event_data = [{"timestamp": ts, "event_type": kind, "details": details} for ts, kind, details in stream]
    _write_json(run / "events.json", event_data)
    report["events_sha256"] = _digest((run / "events.json").read_bytes())

    for mode in MODES:
        identity = f"experiment-{mode}"  # trusted configuration; never inferred from log contents
        original = run / "logs" / mode / "original.jsonl"
        keys, anchors = run / "trusted" / mode / "keys", run / "trusted" / mode / "checkpoints"
        baseline = {"status": "ERROR", "stage": "logging", "expected_log_id": identity,
                    "artifact": str(original.relative_to(run)), "sha256": None,
                    "checkpoint_snapshot_sha256": None,
                    "verifier_result": None, "explanation": "Baseline was not established."}
        report["baselines"][mode] = baseline
        source = None
        checkpoint_hash = None
        stage = "logging"
        try:
            if mode in ("C", "D"):
                stage = "key_generation"
                keys.mkdir(parents=True, mode=0o700)
                anchors.mkdir(parents=True, mode=0o700)
                keyring.generate_key("experiment-key", keys)
            stage = "logging"
            if mode == "A":
                logger = loggers.PlaintextLogger(identity, original)
            elif mode == "B":
                logger = loggers.HashChainLogger(identity, original)
            elif mode == "C":
                logger = loggers.HMACChainLogger(identity, original, "experiment-key", key_store=keys)
            else:
                logger = loggers.HMACCheckpointLogger(identity, original, "experiment-key", anchors,
                                                      key_store=keys, checkpoint_interval=1)
            for ts, kind, details in stream:
                logger.append(ts, kind, deepcopy(details))
            stage = "baseline_verification"
            source = original.read_bytes()
            baseline["sha256"] = _digest(source)
            result = _verify(mode, original, identity, keys, anchors)
            baseline["verifier_result"] = result
            baseline["status"] = "VALID" if result["valid"] else "INVALID"
            baseline["explanation"] = "Untouched log verified." if result["valid"] else "Untouched log failed verification."
            before = _records(original)
            actual_events = [{k: r[k] for k in ("timestamp", "event_type", "details")} for r in before]
            if actual_events != event_data or [r["seq"] for r in before] != list(range(event_count)):
                baseline.update(status="INVALID", explanation="Logged events differ from configured input.")
            elif result["valid"] and result["total_records"] != event_count:
                baseline.update(status="INVALID", explanation="Verifier did not report checking every baseline record.")
            if mode == "D" and baseline["status"] == "VALID":
                stage = "checkpoint_snapshot"
                checkpoint_hash = _checkpoint_digest(identity, anchors)
                baseline["checkpoint_snapshot_sha256"] = checkpoint_hash
            baseline["stage"] = stage
        except Exception as exc:
            if stage in ("baseline_verification", "checkpoint_snapshot"):
                status = _verification_failure(mode, exc)
            elif mode in ("C", "D") and isinstance(exc, (NotImplementedError, KeyError, OSError)):
                status = "BLOCKED"
            else:
                status = "ERROR"
            baseline.update(status=status, stage=stage, exception_type=type(exc).__name__,
                            explanation=f"Baseline unavailable during {stage}; diagnostics omitted to protect secrets.")
            if isinstance(exc, NotImplementedError):
                baseline["explanation"] = f"Required persistence interface is unimplemented ({stage})."
        blocked = baseline["status"] != "VALID"

        for name in ATTACKS:
            row = {"mode": mode, "expected_log_id": identity, "attack": name,
                   "target": deepcopy(plan[name]), "outcome": "BLOCKED", "stage": "prerequisite",
                   "attack_applied": False, "steps": [], "artifacts": {}, "verifier_result": None,
                   "checkpoint_snapshot_sha256": None,
                   "control_result": None, "first_bad_seq": None,
                   "explanation": "A verified, unchanged baseline and trusted dependencies are required."}
            report["results"].append(row)
            if blocked:
                continue
            case = run / "attacks" / mode / name
            staged = case / "input.jsonl"
            staged_written = False
            try:
                row["stage"] = "attack"
                case.mkdir(parents=True)
                if original.read_bytes() != source:
                    raise ValueError("original evidence changed")
                with open(staged, "xb") as destination:
                    destination.write(source)
                staged_written = True
                attacked, steps = _apply(mode, name, staged, plan[name])
                row["steps"] = steps
                if attacked.parent.resolve() != case.resolve() or attacked.is_symlink():
                    raise ValueError("attack output escaped its isolated directory")
                after = _records(attacked)
                _check_effect(mode, name, before, after, plan[name])
                if staged.read_bytes() != source or original.read_bytes() != source:
                    raise ValueError("attack changed its source evidence")
                row["attack_applied"] = True
                row["artifacts"] = {str(p.relative_to(run)): _digest(p.read_bytes())
                                    for p in sorted(case.iterdir()) if p.is_file()}
                row["stage"] = "verification"
                result = _verify(mode, attacked, identity, keys, anchors)
                row["verifier_result"] = result
                row["first_bad_seq"] = result["first_bad_seq"]
                if result["valid"] and result["total_records"] != len(after):
                    raise ValueError("verifier did not report checking every attacked record")
                row["outcome"] = "MISSED" if result["valid"] else "DETECTED"
                row["explanation"] = result["error"] or (
                    "Verifier accepted the controlled attacked artifact." if result["valid"]
                    else "Verifier rejected the controlled attacked artifact.")
            except Exception as exc:
                row["outcome"] = (_verification_failure(mode, exc)
                                  if row["stage"] == "verification" else "ERROR")
                row["exception_type"] = type(exc).__name__
                row["explanation"] = f"{row['stage']} failed; diagnostics omitted to protect secrets."

            # A bad untouched control or altered anchors prevent attributing a
            # failure to the attack (e.g. a historical key changed mid-run).
            try:
                if original.read_bytes() != source or (staged_written and staged.read_bytes() != source):
                    raise ValueError("source evidence changed")
                if mode == "D":
                    current_hash = _checkpoint_digest(identity, anchors)
                    row["checkpoint_snapshot_sha256"] = current_hash
                    if current_hash != checkpoint_hash:
                        raise ValueError("trusted checkpoints changed")
                control = _verify(mode, original, identity, keys, anchors)
                row["control_result"] = control
                if not control["valid"] or control["total_records"] != event_count:
                    row.update(outcome="CANNOT_VERIFY", stage="control_validation",
                               explanation="Untouched control failed; detection cannot be attributed to the attack.")
                    blocked = True
            except Exception as exc:
                # Integrity violations are ERROR; unavailable trusted snapshots
                # are CANNOT_VERIFY, never successful attack detection.
                status = "ERROR" if isinstance(exc, ValueError) else _verification_failure(mode, exc)
                row.update(outcome=status, stage="control_validation",
                           explanation="Evidence/control validation failed; no detection claim is made.",
                           control_exception_type=type(exc).__name__)
                blocked = True

    _write_json(run / "results.json", report)
    with open(run / "matrix.md", "x", encoding="utf-8", newline="\n") as destination:
        destination.write(render_matrix(report))
    return report
