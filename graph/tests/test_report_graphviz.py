from unittest import TestCase

import pytest

from report_graphviz import _parse_args, _unique_dot_id, generate_dot




checks = TestCase()


def test_generate_dot_escapes_backslash_quote_and_newline_in_labels():
    dot = generate_dot(
        [
            {
                "id": "1",
                "label": "Application",
                "display": 'evil\\"] URL="javascript:alert(1)\nnext',
                "bundle_id": "",
            }
        ],
        [],
    )

    label_line = next(line for line in dot.splitlines() if "label=" in line)

    checks.assertNotIn('URL="', label_line)
    checks.assertIn("\\\\\\", label_line)
    checks.assertIn("\\n", label_line)


def test_unique_dot_id_disambiguates_sanitized_identifier_collisions():
    seen: set[str] = set()

    checks.assertEqual(_unique_dot_id("name/with space", seen), "name_with_space")
    checks.assertEqual(_unique_dot_id("name with/space", seen), "name_with_space_1")


def test_parse_args_uses_defaults_and_requires_output(capsys):
    args = _parse_args(["--output", "graph.dot"])

    checks.assertEqual(args.neo4j, "bolt://localhost:7687")
    checks.assertEqual(args.username, "neo4j")
    checks.assertEqual(args.output, "graph.dot")
    with pytest.raises(SystemExit) as error:
        _parse_args([])
    checks.assertEqual(error.value.code, 2)
    checks.assertIn("the following arguments are required: --output", capsys.readouterr().err)


def test_generate_dot_skips_edges_with_missing_endpoint_nodes():
    dot = generate_dot(
        [{"id": "known", "label": "Application", "display": "Known"}],
        [
            {"src_id": "known", "dst_id": "missing", "rel_type": "CAN_INJECT_INTO"},
            {"src_id": "missing", "dst_id": "known", "rel_type": "CAN_INJECT_INTO"},
        ],
    )

    checks.assertNotIn(" -> ", dot)
