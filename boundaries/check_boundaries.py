"""Enforce architecture boundaries across projects — deterministic, stdlib-only.

One philosophy, multiple isolated systems. This makes "no coupling" a CI gate,
not a hope. It maps every .py file to a layer (by the top-level package it lives
in), parses its imports, and fails if any import crosses a forbidden edge.

    python boundaries/check_boundaries.py <path> [<path> ...] --policy boundaries/policy.json

Exit code 1 on any violation, so it can sit directly in CI.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path


def load_policy(path: str):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    root_to_layer: dict[str, str] = {}
    for layer, pkgs in data["layers"].items():
        for pkg in pkgs:
            root_to_layer[pkg] = layer
    forbidden: dict[tuple[str, str], str] = {}
    for rule in data["forbidden"]:
        forbidden[(rule["from"], rule["to"])] = rule.get("why", "")
    return root_to_layer, forbidden


def layer_of_file(path: Path, root_to_layer: dict[str, str]) -> str | None:
    for part in path.parts:
        if part in root_to_layer:
            return root_to_layer[part]
    return None


def imported_roots(tree: ast.AST):
    """Yield (top_level_module, lineno) for every absolute import."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0], node.lineno
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import -> same package, not a boundary crossing
                continue
            if node.module:
                yield node.module.split(".")[0], node.lineno


def forbidden_edge(src: str, dst: str, forbidden) -> tuple[str, str] | None:
    if (src, dst) in forbidden:
        return (src, dst)
    if (src, "*") in forbidden and dst != src:  # philosophy -> any implementation
        return (src, "*")
    return None


def check(paths, policy_path):
    root_to_layer, forbidden = load_policy(policy_path)
    violations = []
    for root in paths:
        for py in sorted(Path(root).rglob("*.py")):
            src_layer = layer_of_file(py, root_to_layer)
            if src_layer is None:
                continue
            try:
                tree = ast.parse(py.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            for mod_root, lineno in imported_roots(tree):
                dst_layer = root_to_layer.get(mod_root)
                if dst_layer is None or dst_layer == src_layer:
                    continue
                edge = forbidden_edge(src_layer, dst_layer, forbidden)
                if edge:
                    violations.append((py, lineno, src_layer, dst_layer, mod_root, forbidden[edge]))
    return violations


def main(argv):
    if "--policy" in argv:
        i = argv.index("--policy")
        policy_path = argv[i + 1]
        paths = argv[:i] + argv[i + 2:]
    else:
        policy_path = "boundaries/policy.json"
        paths = argv
    if not paths:
        print("usage: check_boundaries.py <path> [<path> ...] --policy <policy.json>")
        return 2

    violations = check(paths, policy_path)
    if not violations:
        print(f"OK — no forbidden cross-layer imports under {', '.join(paths)}")
        return 0

    print(f"BOUNDARY VIOLATIONS ({len(violations)}):\n")
    for py, lineno, src, dst, mod, why in violations:
        print(f"  {py}:{lineno}")
        print(f"      {src}  ->  {dst}   (import '{mod}')")
        print(f"      forbidden: {why}\n")
    return 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main(sys.argv[1:]))
