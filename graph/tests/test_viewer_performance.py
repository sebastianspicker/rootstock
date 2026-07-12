import json
from pathlib import Path
import shutil
import subprocess

import pytest


RUNNER = Path(__file__).with_name("viewer_performance.js")


def test_large_graph_interaction_budget():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the viewer performance contract")

    completed = subprocess.run(
        [node, str(RUNNER)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    result = json.loads(completed.stdout)
    assert result["fixture"] == {"nodes": 10_000, "edges": 50_000}
    assert result["hitTestP95Ms"] < 16
    assert result["filterP95Ms"] < 100
