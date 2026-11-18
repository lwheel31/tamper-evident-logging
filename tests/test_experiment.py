"""Orchestration tests. Security-store doubles do not establish integration."""

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tamperlog import checkpoints, experiment, keyring, loggers, verifier

SECRET = b"synthetic-test-key-never-export!!" * 2


@pytest.fixture
def stores(monkeypatch):
    keys, anchors = {}, {}

    def generate(identity, store):
        keys[(store, identity)] = SECRET
        with open(store / f"{identity}.key", "xb") as output:
            output.write(SECRET)

    def load(identity, store):
        return keys[(store, identity)]

    def create(identity, seq, tag, store):
        checkpoint = checkpoints.Checkpoint(identity, seq, tag)
        anchors.setdefault((store, identity), []).append(checkpoint)
        with open(store / f"{identity}_cp_{seq}.json", "x") as output:
            json.dump(asdict(checkpoint), output)
        return checkpoint

    def all_checkpoints(identity, store):
        return deepcopy(anchors.get((store, identity), []))

    monkeypatch.setattr(keyring, "generate_key", generate)
    monkeypatch.setattr(keyring, "load_key", load)
    monkeypatch.setattr(checkpoints, "create_checkpoint", create)
    monkeypatch.setattr(checkpoints, "load_checkpoints", all_checkpoints)
    return keys, anchors


def rows_for(report, mode):
    return [row for row in report["results"] if row["mode"] == mode]


def test_complete_mocked_matrix_and_export(tmp_path, stores):
    report = experiment.run_experiment(output_dir=tmp_path)
    run = Path(report["run_directory"])
    assert report["parameters"]["event_count"] == 50
    assert report["parameters"]["seed"] == 42
    assert report["parameters"]["payroll_export_seq"] == 25
    assert report["source_sha256"]["experiment.py"] == hashlib.sha256(Path(experiment.__file__).read_bytes()).hexdigest()
    assert len(report["results"]) == 16
    assert {(r["mode"], r["attack"]) for r in report["results"]} == {
        (mode, attack) for mode in "ABCD" for attack in experiment.ATTACKS}
    assert all(b["status"] == "VALID" for b in report["baselines"].values())
    assert all(b["verifier_result"]["total_records"] == 50 for b in report["baselines"].values())
    for mode in "AB":
        assert {r["outcome"] for r in rows_for(report, mode)} == {"MISSED"}
    assert [r["outcome"] for r in rows_for(report, "C")] == ["DETECTED"] * 3 + ["MISSED"]
    assert {r["outcome"] for r in rows_for(report, "D")} == {"DETECTED"}
    assert all(r["attack_applied"] for r in report["results"])
    assert all(r["control_result"]["valid"] for r in report["results"])
    assert all(r["checkpoint_snapshot_sha256"] == report["baselines"]["D"]["checkpoint_snapshot_sha256"]
               for r in rows_for(report, "D"))
    assert rows_for(report, "D")[-1]["first_bad_seq"] == 25
    assert json.loads((run / "results.json").read_text()) == report
    assert (run / "matrix.md").read_text() == experiment.render_matrix(report)
    assert SECRET.decode() not in (run / "results.json").read_text()
    assert SECRET.decode() not in (run / "matrix.md").read_text()
    assert all("trusted/" not in path for row in report["results"] for path in row["artifacts"])


def test_attack_isolation_same_events_and_preservation(tmp_path, stores):
    report = experiment.run_experiment(output_dir=tmp_path)
    run = Path(report["run_directory"])
    expected_events = json.loads((run / "events.json").read_text())
    for mode in "ABCD":
        baseline = report["baselines"][mode]
        original = run / baseline["artifact"]
        raw = original.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == baseline["sha256"]
        records = experiment._records(original)
        assert [{key: r[key] for key in ("timestamp", "event_type", "details")} for r in records] == expected_events
        for attack in experiment.ATTACKS:
            assert (run / "attacks" / mode / attack / "input.jsonl").read_bytes() == raw
        for row in rows_for(report, mode):
            for relative, digest in row["artifacts"].items():
                assert hashlib.sha256((run / relative).read_bytes()).hexdigest() == digest
    _, anchors = stores
    assert len(next(iter(anchors.values()))) == 50
    cp_files = list((run / "trusted" / "D" / "checkpoints").glob("*.json"))
    assert len(cp_files) == 50
    for cp_file in cp_files:
        cp = json.loads(cp_file.read_text())
        original = experiment._records(run / "logs" / "D" / "original.jsonl")
        assert cp["tag"] == original[cp["seq"]]["tag"]


def test_reproducibility_and_run_isolation(tmp_path):
    first = experiment.run_experiment(output_dir=tmp_path, event_count=12, seed=7)
    old_files = {p.relative_to(first["run_directory"]): p.read_bytes()
                 for p in Path(first["run_directory"]).rglob("*") if p.is_file()}
    second = experiment.run_experiment(output_dir=tmp_path, event_count=12, seed=7)
    different = experiment.run_experiment(output_dir=tmp_path, event_count=12, seed=8)
    assert first["run_directory"] != second["run_directory"]
    assert first["events_sha256"] == second["events_sha256"] != different["events_sha256"]
    assert first["parameters"] == second["parameters"]
    assert [(r["mode"], r["attack"], r["outcome"]) for r in first["results"]] == [
        (r["mode"], r["attack"], r["outcome"]) for r in second["results"]]
    for mode in "AB":
        assert first["baselines"][mode]["sha256"] == second["baselines"][mode]["sha256"]
        assert [r["artifacts"] for r in rows_for(first, mode)] == [r["artifacts"] for r in rows_for(second, mode)]
    assert {p.relative_to(first["run_directory"]): p.read_bytes()
            for p in Path(first["run_directory"]).rglob("*") if p.is_file()} == old_files


def test_security_setup_unavailable_does_not_block_real_ab(tmp_path, monkeypatch):
    def unavailable(*args):
        raise NotImplementedError(SECRET.decode())
    monkeypatch.setattr(keyring, "generate_key", unavailable)
    report = experiment.run_experiment(output_dir=tmp_path)
    assert {r["outcome"] for r in report["results"] if r["mode"] in "AB"} == {"MISSED"}
    for mode in "CD":
        assert report["baselines"][mode]["status"] == "BLOCKED"
        assert report["baselines"][mode]["stage"] == "key_generation"
        assert {r["outcome"] for r in rows_for(report, mode)} == {"BLOCKED"}
        assert all(r["verifier_result"] is None and not r["attack_applied"] for r in rows_for(report, mode))
    assert SECRET.decode() not in json.dumps(report)


def test_invalid_baseline_blocks_attacks(tmp_path, stores, monkeypatch):
    monkeypatch.setattr(verifier, "verify_hash_chain", lambda path: verifier.VerificationResult(
        "B", "experiment-B", 50, False, 0, "injected baseline failure"))
    report = experiment.run_experiment(output_dir=tmp_path)
    assert report["baselines"]["B"]["status"] == "INVALID"
    assert {r["outcome"] for r in rows_for(report, "B")} == {"BLOCKED"}
    assert not (Path(report["run_directory"]) / "attacks" / "B").exists()
    assert all(r["verifier_result"] is None for r in rows_for(report, "B"))


def test_baseline_checks_events_not_only_verifier_boolean(tmp_path, monkeypatch):
    append = loggers.PlaintextLogger.append
    def wrong_events(self, ts, kind, details):
        return append(self, ts, kind, {**details, "unexpected": True})
    monkeypatch.setattr(loggers.PlaintextLogger, "append", wrong_events)
    report = experiment.run_experiment(output_dir=tmp_path)
    assert report["baselines"]["A"]["verifier_result"]["valid"] is True
    assert report["baselines"]["A"]["status"] == "INVALID"
    assert {r["outcome"] for r in rows_for(report, "A")} == {"BLOCKED"}
    assert report["baselines"]["B"]["status"] == "VALID"


def test_missing_checkpoints_during_setup_are_blocked(tmp_path, stores, monkeypatch):
    def unavailable(*args):
        raise NotImplementedError("checkpoint module pending")
    monkeypatch.setattr(checkpoints, "create_checkpoint", unavailable)
    report = experiment.run_experiment(output_dir=tmp_path)
    assert report["baselines"]["C"]["status"] == "VALID"
    assert report["baselines"]["D"]["status"] == "BLOCKED"
    assert report["baselines"]["D"]["stage"] == "logging"
    assert all(not r["attack_applied"] for r in rows_for(report, "D"))


def test_unavailable_attack_verification_is_not_detection(tmp_path, stores, monkeypatch):
    verify = verifier.verify_hmac_chain
    def unavailable(path, key_store):
        if path.name != "original.jsonl":
            raise RuntimeError("cannot verify: " + SECRET.decode())
        return verify(path, key_store)
    monkeypatch.setattr(verifier, "verify_hmac_chain", unavailable)
    report = experiment.run_experiment(output_dir=tmp_path)
    assert {r["outcome"] for r in rows_for(report, "C")} == {"CANNOT_VERIFY"}
    assert all(r["verifier_result"] is None and r["attack_applied"] for r in rows_for(report, "C"))
    assert SECRET.decode() not in json.dumps(report)


def test_changed_key_cannot_masquerade_as_detection(tmp_path, stores, monkeypatch):
    keys, _ = stores
    apply = experiment._apply
    def change_key(mode, name, path, target):
        output = apply(mode, name, path, target)
        if mode == "C":
            for location in keys:
                if location[0].parts[-2] == "C":
                    keys[location] = b"wrong-but-well-formed-key-material" * 2
        return output
    monkeypatch.setattr(experiment, "_apply", change_key)
    report = experiment.run_experiment(output_dir=tmp_path)
    first = rows_for(report, "C")[0]
    assert first["verifier_result"]["valid"] is False
    assert first["control_result"]["valid"] is False
    assert first["outcome"] == "CANNOT_VERIFY"
    assert {r["outcome"] for r in rows_for(report, "C")[1:]} == {"BLOCKED"}


def test_changed_checkpoints_are_not_detection(tmp_path, stores, monkeypatch):
    _, anchors = stores
    apply = experiment._apply
    def change_checkpoint(mode, name, path, target):
        output = apply(mode, name, path, target)
        if mode == "D":
            next(iter(anchors.values()))[0].tag = "f" * 64
        return output
    monkeypatch.setattr(experiment, "_apply", change_checkpoint)
    report = experiment.run_experiment(output_dir=tmp_path)
    assert rows_for(report, "D")[0]["outcome"] == "ERROR"
    assert {r["outcome"] for r in rows_for(report, "D")[1:]} == {"BLOCKED"}


def test_noop_attack_is_an_execution_error(tmp_path, monkeypatch):
    monkeypatch.setattr(experiment.attacks, "modify_record", lambda path, seq, details: path)
    report = experiment.run_experiment(output_dir=tmp_path)
    for mode in "AB":
        row = rows_for(report, mode)[0]
        assert row["outcome"] == "ERROR" and not row["attack_applied"]
        assert row["verifier_result"] is None
        assert rows_for(report, mode)[1]["outcome"] == "MISSED"


def test_attack_error_diagnostics_do_not_expose_secrets(tmp_path, monkeypatch):
    def fail(*args):
        raise ValueError(SECRET.decode())
    monkeypatch.setattr(experiment.attacks, "delete_record", fail)
    report = experiment.run_experiment(output_dir=tmp_path)
    assert rows_for(report, "A")[1]["outcome"] == "ERROR"
    assert SECRET.decode() not in json.dumps(report)


@pytest.mark.parametrize("count,seed", [(3, 42), (True, 42), (50, True), (5.0, 42), (50, "42")])
def test_invalid_parameters_do_not_create_runs(tmp_path, count, seed):
    with pytest.raises(ValueError):
        experiment.run_experiment(output_dir=tmp_path, event_count=count, seed=seed)
    assert list(tmp_path.iterdir()) == []


def test_existing_output_file_is_not_overwritten(tmp_path):
    output = tmp_path / "existing"
    output.write_text("evidence")
    with pytest.raises(FileExistsError):
        experiment.run_experiment(output_dir=output)
    assert output.read_text() == "evidence"


def test_cli_execution(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    proc = subprocess.run([sys.executable, "-m", "tamperlog.cli", "experiment",
                           "--output-dir", str(tmp_path), "--event-count", "12", "--seed", "7"],
                          text=True, capture_output=True, env=env)
    assert proc.returncode == 0, proc.stderr
    assert "MISSED" in proc.stdout and "Evidence:" in proc.stdout
    results = list(tmp_path.glob("run-*/results.json"))
    assert len(results) == 1
    report = json.loads(results[0].read_text())
    assert report["parameters"]["event_count"] == 12 and report["parameters"]["seed"] == 7
    assert len(report["results"]) == 16


def test_cli_invalid_count_creates_no_results(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    proc = subprocess.run([sys.executable, "-m", "tamperlog.cli", "experiment",
                           "--output-dir", str(tmp_path), "--event-count", "3"],
                          text=True, capture_output=True, env=env)
    assert proc.returncode != 0
    assert "--event-count must be at least 4" in proc.stderr
    assert list(tmp_path.iterdir()) == []


def test_one_event_generation_and_checkpoint_rollback_detection(tmp_path, stores, monkeypatch):
    from unittest.mock import Mock
    generate = Mock(wraps=experiment.events.generate_events)
    monkeypatch.setattr(experiment.events, "generate_events", generate)
    _, anchors = stores
    apply = experiment._apply
    def rollback(mode, name, path, target):
        output = apply(mode, name, path, target)
        if mode == "D" and name == "truncate":
            values = next(iter(anchors.values()))
            del values[target["keep_count"]:]
        return output
    monkeypatch.setattr(experiment, "_apply", rollback)
    report = experiment.run_experiment(output_dir=tmp_path)
    generate.assert_called_once_with(50, 42)
    row = rows_for(report, "D")[-1]
    assert row["verifier_result"]["valid"] is True  # matching log+checkpoint prefix
    assert row["outcome"] == "ERROR"  # changed trust evidence invalidates scoring


def test_unexpected_verifier_runtime_error_is_not_dependency_failure(tmp_path, stores, monkeypatch):
    verify = verifier.verify_hmac_chain
    def unexpected(path, key_store):
        if path.name != "original.jsonl":
            raise RuntimeError(SECRET.decode())
        return verify(path, key_store)
    monkeypatch.setattr(verifier, "verify_hmac_chain", unexpected)
    report = experiment.run_experiment(output_dir=tmp_path)
    assert {r["outcome"] for r in rows_for(report, "C")} == {"ERROR"}
    assert SECRET.decode() not in json.dumps(report)


def test_unavailable_checkpoint_snapshot_blocks_baseline(tmp_path, stores, monkeypatch):
    load = checkpoints.load_checkpoints
    calls = 0
    def unavailable(identity, store):
        nonlocal calls
        calls += 1
        if calls > 1:  # D baseline verifies, then snapshot retrieval fails
            raise PermissionError(SECRET.decode())
        return load(identity, store)
    monkeypatch.setattr(checkpoints, "load_checkpoints", unavailable)
    report = experiment.run_experiment(output_dir=tmp_path)
    assert report["baselines"]["D"]["status"] == "CANNOT_VERIFY"
    assert {r["outcome"] for r in rows_for(report, "D")} == {"BLOCKED"}
    assert SECRET.decode() not in json.dumps(report)


def test_wrong_baseline_identity_is_not_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier, "verify_plaintext", lambda path: verifier.VerificationResult(
        "A", "substituted-identity", 50, True))
    report = experiment.run_experiment(output_dir=tmp_path)
    assert report["baselines"]["A"]["status"] == "ERROR"
    assert {r["outcome"] for r in rows_for(report, "A")} == {"BLOCKED"}


def test_cli_exception_is_sanitized(tmp_path, monkeypatch, capsys):
    from tamperlog import cli
    def fail(**kwargs):
        raise RuntimeError(SECRET.decode())
    monkeypatch.setattr(experiment, "run_experiment", fail)
    monkeypatch.setattr(sys, "argv", ["tamperlog", "experiment", "--output-dir", str(tmp_path)])
    with pytest.raises(SystemExit) as caught:
        cli.main()
    assert caught.value.code == 1
    output = capsys.readouterr()
    assert "RuntimeError" in output.err
    assert SECRET.decode() not in output.err + output.out


def test_minimum_event_count_with_mocked_stores(tmp_path, stores):
    report = experiment.run_experiment(output_dir=tmp_path, event_count=4, seed=0)
    assert report["parameters"]["payroll_export_seq"] == 2
    assert all(b["status"] == "VALID" for b in report["baselines"].values())
    assert len(report["results"]) == 16
    assert rows_for(report, "D")[-1]["first_bad_seq"] == 2


def test_original_evidence_change_invalidates_scoring(tmp_path, monkeypatch):
    apply = experiment._apply
    def corrupt_original(mode, name, path, target):
        output = apply(mode, name, path, target)
        if mode == "A" and name == "modify":
            original = path.parents[3] / "logs" / mode / "original.jsonl"
            original.write_bytes(b"corrupted by injected faulty attack")
        return output
    monkeypatch.setattr(experiment, "_apply", corrupt_original)
    report = experiment.run_experiment(output_dir=tmp_path)
    assert rows_for(report, "A")[0]["outcome"] == "ERROR"
    assert {r["outcome"] for r in rows_for(report, "A")[1:]} == {"BLOCKED"}
    assert {r["outcome"] for r in rows_for(report, "B")} == {"MISSED"}


def test_baseline_claiming_zero_verified_records_is_not_valid(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier, "verify_plaintext", lambda path: verifier.VerificationResult(
        "A", "experiment-A", 0, True))
    report = experiment.run_experiment(output_dir=tmp_path)
    assert report["baselines"]["A"]["status"] == "INVALID"
    assert {r["outcome"] for r in rows_for(report, "A")} == {"BLOCKED"}


def test_control_must_verify_all_original_records(tmp_path, stores, monkeypatch):
    verify = verifier.verify_hmac_chain
    originals = 0
    def incomplete_control(path, key_store):
        nonlocal originals
        if path.name == "original.jsonl":
            originals += 1
            if originals > 1:
                return verifier.VerificationResult("C", "experiment-C", 0, True)
        return verify(path, key_store)
    monkeypatch.setattr(verifier, "verify_hmac_chain", incomplete_control)
    report = experiment.run_experiment(output_dir=tmp_path)
    row = rows_for(report, "C")[0]
    assert row["verifier_result"]["valid"] is False
    assert row["control_result"]["valid"] is True
    assert row["outcome"] == "CANNOT_VERIFY"
