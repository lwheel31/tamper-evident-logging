# AI Usage Log

This document records AI assistance used during development of the ITIS 6200 Tamper-Evident Logging project.

## 2026-11-15 — Initial Scaffold

- **Tool:** Claude Code (Claude Opus 4.6)
- **Operator:** Lucas Wheeler
- **Task:** Create the initial repository structure, module interfaces, documentation, and test skeletons.
- **Generated:** Project folders, module stubs with `NotImplementedError` placeholders, test skeletons, README, `pyproject.toml`, and initial documentation.
- **Scope:** No security mechanisms, attack implementations, or experiment results were implemented during this session.

## 2026-11-16 — Logging Implementation

- **Tool:** Claude
- **Operator:** Lucas Wheeler
- **Task:** Implement event generation, serialization hardening, and logging Modes A-C with Mode D checkpoint integration.
- **Generated:** `events.py`, serialization updates, logger implementations, and related tests.
- **Design choices:** Sequence numbers begin at zero, chained logs use a public genesis tag, signed data uses deterministic serialization, and existing logs are not overwritten.
- **Validation:** `pytest` reported **21 passed, 17 pending** while remaining team modules were unfinished.

## 2026-11-17 — Verification, Attacks, and Experimentation

- **Tools:** ChatGPT and OpenAI Codex
- **Operator:** Julian Roberts
- **Task:** AI assistance was used for verification across Modes A-D, the four tampering attacks, experiment automation, CLI integration, testing, and reproducibility documentation.
- **Generated:** `verifier.py`, `attacks.py`, `experiment.py`, supporting CLI functionality, regression and adversarial tests, integration tests, and documentation.
- **Design choices:** The work preserved existing interfaces, historical-key verification, trusted Mode D identity, deterministic evidence-preserving attacks, public SHA-256 reconstruction, and baseline/control validation.
- **Validation:** Before persistence integration, testing reached **436 passed, 11 skipped**. Real Modes A/B produced the expected `MISSED` results while C/D remained blocked pending key and checkpoint persistence.

## 2026-11-25 — Final Integration Review

- **Tools:** ChatGPT and OpenAI Codex
- **Operator:** Julian Roberts
- **Task:** AI assistance was used to review the completed key/checkpoint persistence implementation and validate the integrated system.
- **Generated:** Targeted regression tests, narrowly scoped persistence corrections, integration checks, and documentation updates.
- **Review findings:** Testing identified Windows binary-key write behavior, a concurrent checkpoint publication issue, incomplete write handling, and stricter checkpoint parsing requirements.
- **Validation:** The corrected implementation reported **485 passed, 0 skipped** in Ubuntu and **482 passed, 3 platform-specific failures** on Windows. Repeated installed CLI runs reproduced the expected 16-cell experiment matrix.

AI assistance supported implementation, testing, review, and documentation. Final responsibility for understanding the project, its security mechanisms, and its limitations remains with the team members presenting and submitting the work.

## 2026-11-26 — Presentation UI Integration

- **Tools:** ChatGPT and OpenAI Codex
- **Operator:** Julian Roberts
- **Task:** AI assistance was used to build and refine a Streamlit presentation interface for demonstrating the completed experiment without duplicating or modifying the underlying security logic.
- **Generated:** `ui/app.py`, `ui/presentation.py`, `ui/style.css`, and the optional Streamlit dependency configuration.
- **Design choices:** The UI was structured to call the existing experiment runner, display actual generated artifacts and verifier results, and keep logging, attack, verification, key, and checkpoint logic inside the existing `tamperlog` modules. The interface was later simplified to focus on Overview, Live Attack Demo, and Results for the final presentation.
- **Validation:** The UI was exercised across all 16 mode/attack combinations, verified against the recorded experiment matrix, and checked to ensure no security implementation files or trusted key/checkpoint data were exposed or modified.