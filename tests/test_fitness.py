"""Mutation tests for the credential-free architectural and guide sensors."""

from pathlib import Path

import pytest
from infra_core import fitness, verification

ROOT = Path(__file__).resolve().parents[1]


def write(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "module, source",
    [
        ("cli.py", "import pulumi as sdk"),
        ("config.py", "from infra_program import governance"),
        ("governance/audit.py", "from ..inventory import oci"),
        ("governance/audit.py", "from infra_core import cli"),
        ("oci/graph.py", "def lazy():\n    import subprocess"),
        ("kubernetes/audit.py", "import socket"),
        ("services/governance.py", "import urllib.request"),
        ("governance/__init__.py", "from .. import backend"),
        ("cli.py", "from importlib import import_module as load\nload('pulumi')"),
        ("cli.py", "import importlib as loader\nloader.import_module('infra_program')"),
        ("cli.py", "__import__('pulumi_oci')"),
        ("cli.py", "import importlib\nimportlib.import_module(name)"),
        ("cli.py", "import importlib\nimportlib.import_module('.governance', 'infra_program')"),
    ],
)
def test_forbidden_imports_fail_with_source_location(tmp_path, module, source):
    path = write(tmp_path, "packages/infra-core/src/infra_core/" + module, source)
    errors = fitness.architecture_errors(tmp_path)
    assert errors and all("ARCH001" in error for error in errors)
    assert str(path.relative_to(tmp_path)) + ":" in "\n".join(errors)


def test_reviewed_adapters_and_pure_relative_imports_are_allowed(tmp_path):
    for module, source in {
        "governance/audit.py": "from .contracts import number\nfrom decimal import Decimal",
        "oci/graph.py": "from ..governance.contracts import require",
        "inventory/oci.py": "import importlib\nimportlib.import_module('oci')",
        "backend.py": "import subprocess",
    }.items():
        write(tmp_path, "packages/infra-core/src/infra_core/" + module, source)
    write(
        tmp_path,
        "packages/infra-program/src/infra_program/oci/components.py",
        "import pulumi_oci\nfrom infra_core.governance.audit import audit",
    )
    assert fitness.architecture_errors(tmp_path) == []


def docs(root, text):
    write(root, "sdks/AGENTS.md", "# SDKs\n")
    return write(root, "HARNESS.md", text)


@pytest.mark.parametrize("target", ["gone.md", "guide.md#removed", "../outside.md"])
def test_missing_guide_target_or_anchor_fails(tmp_path, target):
    docs(tmp_path, f"# Map\n\n[Guide]({target})\n")
    write(tmp_path, "guide.md", "# Current\n")
    assert fitness.documentation_errors(tmp_path) == [
        f"DOC001 HARNESS.md:3: broken local link {target}"
    ]


def test_reference_links_and_duplicate_anchors(tmp_path):
    docs(tmp_path, "[Guide][g]\n\n[g]: docs/guide.md#repeat-1\n")
    write(tmp_path, "docs/guide.md", "# Repeat\n# Repeat\n[Map](../HARNESS.md)\n")
    assert fitness.documentation_errors(tmp_path) == []
    docs(tmp_path, "[Guide][undefined]\n")
    assert "DOC001" in fitness.documentation_errors(tmp_path)[0]


@pytest.mark.parametrize(
    "command",
    [
        "infra report",
        "infra verify --scope python",
        "infra backend missing",
        "infra oci proposal --typo x",
    ],
)
def test_removed_commands_and_unknown_flags_fail(tmp_path, command):
    docs(tmp_path, f"Run `{command}`.\n")
    assert "DOC002 HARNESS.md:1:" in fitness.documentation_errors(tmp_path)[0]


def test_cli_examples_are_parsed_but_never_executed(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("documentation check executed an operator command")

    from infra_core import cli

    monkeypatch.setattr(cli, "main", forbidden)
    docs(
        tmp_path,
        """```sh
uv run --locked infra backend qualify --allow-backend-writes
uv run --locked infra kubernetes render \\
  --config .infra/private.toml > .infra/output.json
uv run --locked --extra inventory-oci infra governance inventory \\
  --account .infra/account.toml --oci-config .infra/oci.conf
```
[External](https://example.invalid/unreachable)
""",
    )
    assert fitness.documentation_errors(tmp_path) == []
    assert not (tmp_path / ".infra").exists()


def test_real_repository_satisfies_fitness_contracts():
    fitness.check_fitness(ROOT)


def test_failed_fitness_stops_verification_before_tools(tmp_path, monkeypatch):
    monkeypatch.setattr(verification, "check_tracked_artifacts", lambda root: None)
    docs(tmp_path, "[Missing](missing.md)")
    monkeypatch.setattr(verification, "run", lambda *args, **kw: pytest.fail("ran tools"))
    with pytest.raises(RuntimeError, match="DOC001"):
        verification.verify(tmp_path)


def test_fenced_links_are_ignored_and_diagnostics_keep_real_line_numbers(tmp_path):
    docs(tmp_path, "```text\n[Example](absent.md)\n```\n\n[Guide](missing.md)\n")
    assert fitness.documentation_errors(tmp_path) == [
        "DOC001 HARNESS.md:5: broken local link missing.md"
    ]
    docs(tmp_path, "```sh\ninfra verify\ninfra removed\n```\n\nRun `infra missing`.\n")
    errors = fitness.documentation_errors(tmp_path)
    assert any("HARNESS.md:3:" in error for error in errors)
    assert any("HARNESS.md:6:" in error for error in errors)


def test_sdk_exception_does_not_spread_to_other_inventory_modules(tmp_path):
    write(tmp_path, "packages/infra-core/src/infra_core/inventory/other.py", "import oci")
    assert "ARCH001" in fitness.architecture_errors(tmp_path)[0]


def test_forbidden_import_stops_the_shared_gate(tmp_path, monkeypatch):
    monkeypatch.setattr(verification, "check_tracked_artifacts", lambda root: None)
    docs(tmp_path, "# Map\n")
    write(tmp_path, "packages/infra-core/src/infra_core/oci/graph.py", "import pulumi")
    monkeypatch.setattr(verification, "run", lambda *args, **kw: pytest.fail("ran tools"))
    with pytest.raises(RuntimeError, match="ARCH001"):
        verification.verify(tmp_path)
