"""Composition entry point; offline commands do not import the Pulumi runtime."""

import argparse
from collections.abc import Sequence
from pathlib import Path

from infra_core.cli import main as core_main


def _preview(root: Path, args: argparse.Namespace) -> None:
    from infra_program.preview_orchestration import execute

    execute(root, args)


def main(argv: Sequence[str] | None = None) -> int:
    return core_main(argv, preview=_preview)
