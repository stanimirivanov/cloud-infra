"""Static first-party import and local Markdown/CLI contracts; never run examples."""

import ast
import contextlib
import io
import re
import shlex
import sys
from importlib.util import resolve_name
from pathlib import Path
from urllib.parse import unquote, urlsplit

PURE = {"governance", "oci", "kubernetes", "services"}
PURE_STDLIB = {
    "__future__",
    "calendar",
    "collections",
    "copy",
    "dataclasses",
    "datetime",
    "decimal",
    "enum",
    "functools",
    "ipaddress",
    "itertools",
    "json",
    "math",
    "operator",
    "pathlib",
    "re",
    "statistics",
    "string",
    "tomllib",
    "typing",
}
PROGRAM = {"pulumi", "pulumi_policy", "pulumi_oci", "pulumi_cloudflare", "pulumi_supabase"}


def _within(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(prefix + ".")


def _allowed(owner: str, target: str) -> bool:
    top = target.split(".")[0]
    domain = owner.split(".")[1] if owner.startswith("infra_core.") else ""
    if domain in PURE:
        return top in PURE_STDLIB or any(
            _within(target, "infra_core." + name) for name in {domain, "governance"}
        )
    if owner.startswith("infra_core"):
        return (
            top in sys.stdlib_module_names
            or top == "infra_core"
            or (owner == "infra_core.inventory.oci" and top == "oci")
            or (
                owner == "infra_core.review_signatures"
                and target
                in {
                    "cryptography.exceptions.InvalidSignature",
                    "cryptography.exceptions.UnsupportedAlgorithm",
                    "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey",
                }
            )
        )
    return top in sys.stdlib_module_names or top in PROGRAM | {"infra_core", "infra_program"}


def architecture_errors(root: Path) -> list[str]:
    errors = []
    sources = [
        root / "packages/infra-core/src",
        root / "packages/infra-program/src",
        root / "policies",
    ]
    for source in sources:
        for path in sorted(source.rglob("*.py")):
            parts = list(path.relative_to(source).with_suffix("").parts)
            if parts[-1] == "__init__":
                parts.pop()
            owner = ".".join(parts)
            package = owner if path.name == "__init__.py" else owner.rpartition(".")[0]
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            # Resolve aliases so lazy/dynamic imports cannot bypass the same rule.
            aliases = {}
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        aliases[alias.asname or alias.name] = alias.name
                elif isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            for node in ast.walk(tree):
                targets: list[str] = []
                if isinstance(node, ast.Import):
                    targets = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    base = node.module or ""
                    if node.level:
                        try:
                            base = resolve_name("." * node.level + base, package)
                        except (ImportError, ValueError):
                            base = "invalid_relative_import"
                    targets = [base + "." + alias.name for alias in node.names]
                elif isinstance(node, ast.Call):
                    name = ast.unparse(node.func)
                    first, dot, rest = name.partition(".")
                    name = aliases.get(first, first) + (dot + rest if dot else "")
                    if name in {"__import__", "builtins.__import__", "importlib.import_module"}:
                        value = node.args[0] if node.args else None
                        if isinstance(value, ast.Constant) and isinstance(value.value, str):
                            target = value.value
                            if target.startswith("."):
                                # Dynamic relative imports need an explicit literal package.
                                pkg = (
                                    node.args[1]
                                    if len(node.args) > 1
                                    else next(
                                        (kw.value for kw in node.keywords if kw.arg == "package"),
                                        None,
                                    )
                                )
                                try:
                                    target = resolve_name(
                                        target,
                                        pkg.value
                                        if isinstance(pkg, ast.Constant)
                                        and isinstance(pkg.value, str)
                                        else "",
                                    )
                                except (ImportError, ValueError):
                                    target = "unresolved_dynamic_import"
                            targets = [target]
                        else:
                            targets = ["unresolved_dynamic_import"]
                for target in targets:
                    if not _allowed(owner, target):
                        errors.append(
                            f"ARCH001 {path.relative_to(root)}:{getattr(node, 'lineno', 1)}: "
                            f"{owner} may not import {target}"
                        )
    return errors


def _slugs(text: str) -> set[str]:
    result: set[str] = set()
    text = re.sub(r"(?ms)^```.*?^```[^\n]*", "", text)
    for heading in re.findall(r"^ {0,3}#{1,6}\s+(.+?)\s*#*\s*$", text, re.MULTILINE):
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        candidate = slug
        count = 0
        while candidate in result:
            count += 1
            candidate = f"{slug}-{count}"
        result.add(candidate)
    return result


def documentation_errors(root: Path) -> list[str]:
    # Local import prevents the CLI -> verify -> fitness -> CLI initialization cycle.
    from infra_core.cli import build_parser

    parser = build_parser()
    documents = set(root.glob("*.md"))
    for directory in ("docs", "packages", "config", ".github"):
        documents.update((root / directory).rglob("*.md"))
    documents.add(root / "sdks/AGENTS.md")
    errors: list[str] = []
    for path in sorted(documents):
        text = path.read_text(encoding="utf-8")
        prose = re.sub(r"(?ms)^```.*?^```[^\n]*", lambda m: re.sub(r"[^\n]", " ", m.group()), text)
        definitions = {
            key.lower(): target
            for key, target in re.findall(r"(?m)^\s*\[([^\]]+)\]:\s*<?([^\s>]+)>?", prose)
        }
        links = [
            (m.start(), m.group(1))
            for m in re.finditer(r"\[[^\]\n]+\]\(<?([^\s)>]+)>?(?:\s+\"[^\"]*\")?\)", prose)
        ]
        for match in re.finditer(r"\[([^\]\n]+)\]\[([^\]\n]*)\]", prose):
            key = (match.group(2) or match.group(1)).lower()
            links.append((match.start(), definitions.get(key, "missing-reference:" + key)))
        for offset, target in links:
            line = prose.count("\n", 0, offset) + 1
            url = urlsplit(target)
            if url.netloc or (url.scheme and url.scheme != "missing-reference"):
                continue
            destination = (path.parent / unquote(url.path)).resolve() if url.path else path
            valid = destination.is_relative_to(root.resolve()) and destination.exists()
            if valid and url.fragment and destination.suffix == ".md":
                valid = unquote(url.fragment) in _slugs(destination.read_text(encoding="utf-8"))
            if url.scheme == "missing-reference" or not valid:
                errors.append(f"DOC001 {path.relative_to(root)}:{line}: broken local link {target}")
        # Validate full commands in inline code and shell fences, including continuations.
        snippets = [(m.start(1), m.group(1)) for m in re.finditer(r"`([^`\n]+)`", prose)]
        snippets += [
            (m.start(1), m.group(1))
            for m in re.finditer(r"(?ms)^```(?:sh|bash|shell|console)?\n(.*?)^```", text)
        ]
        for offset, snippet in snippets:
            for match in re.finditer(r"(?:[^\n]*\\\n)*[^\n]+", snippet):
                command = match.group().replace("\\\n", " ").strip().removeprefix("$ ")
                if not re.match(r"^(?:uv run\b.*?\s)?infra\s", command):
                    continue
                line = text.count("\n", 0, offset) + snippet.count("\n", 0, match.start()) + 1
                try:
                    tokens = shlex.split(command)
                    args = tokens[tokens.index("infra") + 1 :]
                    # Output redirection is shell syntax, never a CLI argument.
                    args = args[
                        : next(
                            (i for i, token in enumerate(args) if token in {">", ">>"}), len(args)
                        )
                    ]
                    with (
                        contextlib.redirect_stderr(io.StringIO()),
                        contextlib.redirect_stdout(io.StringIO()),
                    ):
                        parser.parse_args(args)
                except (ValueError, SystemExit) as error:
                    if isinstance(error, SystemExit) and error.code == 0:
                        continue
                    errors.append(
                        f"DOC002 {path.relative_to(root)}:{line}: invalid infra command: {command}"
                    )
    return errors


def check_fitness(root: Path) -> None:
    errors = architecture_errors(root) + documentation_errors(root)
    if errors:
        raise RuntimeError("Repository fitness failed:\n" + "\n".join(errors))
