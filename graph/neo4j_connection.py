"""
neo4j_connection.py — Shared Neo4j connection helpers for Rootstock CLIs.

Provides unified argparse arguments, driver creation, and error handling
used by import.py, infer.py, report.py, and query_runner.py.
"""

from __future__ import annotations

import argparse
import sys

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable, AuthError


def add_neo4j_args(parser: argparse.ArgumentParser) -> None:
    """Add the standard --neo4j, --username, --password arguments."""
    parser.add_argument("--neo4j", default="bolt://localhost:7687", dest="uri",
                        help="Neo4j bolt URI (default: bolt://localhost:7687)")
    parser.add_argument("--username", default="neo4j",
                        help="Neo4j username (default: neo4j)")
    parser.add_argument("--password", default="rootstock",
                        help="Neo4j password (default: rootstock)")


def connect(uri: str, username: str, password: str, *, quiet: bool = False):
    """
    Create and verify a Neo4j driver connection.

    Returns the driver on success, or calls sys.exit(1) on failure.
    """
    if not quiet:
        print(f"Connecting to Neo4j at {uri}...")
    try:
        driver = GraphDatabase.driver(uri, auth=(username, password))
        driver.verify_connectivity()
    except ServiceUnavailable:
        print(f"ERROR: Cannot connect to Neo4j at {uri}", file=sys.stderr)
        sys.exit(1)
    except AuthError:
        print("ERROR: Authentication failed. Check --username / --password.", file=sys.stderr)
        sys.exit(1)
    return driver


def connect_from_args(args):
    """Create a driver from parsed argparse namespace (expects .uri, .username, .password)."""
    return connect(args.uri, args.username, args.password)
