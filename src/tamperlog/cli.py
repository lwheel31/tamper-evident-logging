"""Command-line interface.

Proposed commands (awaiting team approval):
    tamperlog generate   — create synthetic events and log them in all modes
    tamperlog verify     — verify a specific log file
    tamperlog attack     — apply a named attack to a log file
    tamperlog experiment — run the full comparison experiment
    tamperlog keys       — manage HMAC keys (generate, rotate, list)

Owner: ALL
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import experiment


def main() -> None:
    """Entry point for the CLI.

    TODO (ALL): Wire up subcommands to the appropriate module functions.
    """
    parser = argparse.ArgumentParser(
        prog="tamperlog",
        description="Tamper-evident logging — ITIS 6200 project",
    )
    subparsers = parser.add_subparsers(dest="command")

    experiment_parser = subparsers.add_parser("experiment", help="Run the reproducible mode/attack matrix")
    experiment_parser.add_argument("--output-dir", type=Path, default=Path("experiment-results"))
    experiment_parser.add_argument("--event-count", type=int, default=50)
    experiment_parser.add_argument("--seed", type=int, default=42)

    # TODO (Lucas): Add 'generate' subcommand
    # TODO (Julian): Add 'verify' and 'attack' subcommands
    # TODO (Ashton): Add 'keys' subcommand

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
    elif args.command == "experiment":
        if args.event_count < 4:
            parser.error("--event-count must be at least 4")
        try:
            report = experiment.run_experiment(output_dir=args.output_dir,
                                               event_count=args.event_count, seed=args.seed)
        except Exception as exc:
            # Backend exceptions must not print potential key material.
            parser.exit(1, f"Experiment failed ({type(exc).__name__}); no complete report was produced.\n")
        print(experiment.render_matrix(report))
        print(f"Evidence: {Path(report['run_directory']) / 'results.json'}")
    else:
        raise NotImplementedError(f"Command '{args.command}' not yet implemented")


if __name__ == "__main__":
    main()
