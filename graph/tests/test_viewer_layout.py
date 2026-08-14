import math
from unittest import TestCase
from unittest.mock import patch

import viewer_layout
from viewer_layout import compute_layout


def _fixture_nodes() -> list[dict]:
    return [
        {"id": "app-1", "kind": "Application"},
        {"id": "grant-1", "kind": "TCCGrant"},
        {"id": "svc-1", "kind": "Service"},
    ]


def _grid_nodes(count: int) -> list[dict]:
    return [
        {"id": f"node-{index}", "kind": f"kind-{index}"}
        for index in range(count)
    ]


checks = TestCase()


def test_compute_layout_is_deterministic_and_clamps_to_viewport():
    edges = [
        {"source": "app-1", "target": "grant-1"},
        {"source": "missing", "target": "svc-1"},
    ]
    first = _fixture_nodes()
    second = _fixture_nodes()

    compute_layout(first, edges, width=400, height=300, iterations=5)
    compute_layout(second, edges, width=400, height=300, iterations=5)

    checks.assertEqual(
        [(node["x"], node["y"]) for node in first],
        [(node["x"], node["y"]) for node in second],
    )
    checks.assertTrue(all(50 <= node["x"] <= 350 for node in first))
    checks.assertTrue(all(50 <= node["y"] <= 250 for node in first))


def test_compute_layout_leaves_empty_graph_unchanged():
    nodes: list[dict] = []

    compute_layout(nodes, [], iterations=1)

    checks.assertEqual(nodes, [])


def test_compute_layout_uses_grid_repulsion_only_above_threshold():
    modes: list[str] = []

    def record(mode: str):
        def apply(
            nodes: list[dict],
            fx: list[float],
            fy: list[float],
            effective_repulsion: float,
            min_dist: float,
        ) -> None:
            modes.append(mode)

        return apply

    with (
        patch.object(viewer_layout, "_apply_full_repulsion", record("full")),
        patch.object(viewer_layout, "_apply_grid_repulsion", record("grid")),
    ):
        compute_layout(_grid_nodes(3000), [], iterations=1)
        compute_layout(_grid_nodes(3001), [], iterations=1)

    checks.assertEqual(modes, ["full", "grid"])


def test_compute_layout_grid_mode_is_deterministic_clamped_and_rounded():
    first = _grid_nodes(3001)
    second = _grid_nodes(3001)
    edges = [{"source": "node-0", "target": "node-3000"}]

    compute_layout(first, edges, width=100_000, height=100_000, iterations=2)
    compute_layout(second, edges, width=100_000, height=100_000, iterations=2)

    positions = [(node["x"], node["y"]) for node in first]
    checks.assertEqual(positions, [(node["x"], node["y"]) for node in second])
    checks.assertTrue(
        all(50 <= x <= 99_950 and 50 <= y <= 99_950 for x, y in positions)
    )
    checks.assertTrue(all(x == round(x, 1) and y == round(y, 1) for x, y in positions))


def test_compute_layout_keeps_coincident_clamped_positions_finite():
    nodes = [
        {"id": "node-1", "kind": "Application"},
        {"id": "node-2", "kind": "Application"},
        {"id": "node-3", "kind": "Application"},
    ]

    compute_layout(nodes, [], width=100, height=100, iterations=2)

    positions = [(node["x"], node["y"]) for node in nodes]
    checks.assertTrue(all(math.isfinite(value) for position in positions for value in position))
    checks.assertEqual(positions, [(50.0, 50.0)] * len(nodes))
