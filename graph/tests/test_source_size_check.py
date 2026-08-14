from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[2] / "scripts" / "check-source-size.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_source_size", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_untracked_maintained_source_is_checked(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    oversized = tmp_path / "oversized.py"
    oversized.write_text("line\n" * 601, encoding="utf-8")

    checker = _load_checker()
    monkeypatch.setattr(checker, "ROOT", tmp_path)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT)])

    assert checker.main() == 1
    output = capsys.readouterr().out
    assert "oversized.py: 601 lines (limit: 600)" in output
