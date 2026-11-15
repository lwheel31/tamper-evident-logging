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


def main() -> None:
    """Entry point for the CLI.

    TODO (ALL): Wire up subcommands to the appropriate module functions.
    """
    parser = argparse.ArgumentParser(
        prog="tamperlog",
        description="Tamper-evident logging — ITIS 6200 project",
    )
    subparsers = parser.add_subparsers(dest="command")

    # TODO (Lucas): Add 'generate' subcommand
    # TODO (Julian): Add 'verify', 'attack', 'experiment' subcommands
    # TODO (Ashton): Add 'keys' subcommand

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
    else:
        raise NotImplementedError(f"Command '{args.command}' not yet implemented")


if __name__ == "__main__":
    main()
