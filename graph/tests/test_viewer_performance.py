import json
import os
import select
import shutil
import time

import pytest


def test_large_graph_interaction_budget():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the viewer performance contract")

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.dup2(write_fd, 1)
        os.dup2(write_fd, 2)
        os.close(read_fd)
        os.close(write_fd)
        os.execv("/usr/bin/env", ["env", "node", "graph/tests/viewer_performance.js"])
    os.close(write_fd)
    deadline = time.monotonic() + 30
    output = bytearray()
    while True:
        waited_pid, status = os.waitpid(pid, os.WNOHANG)
        if waited_pid == pid:
            output.extend(os.read(read_fd, 1 << 20))
            break
        if time.monotonic() >= deadline:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            os.close(read_fd)
            raise AssertionError("viewer performance runner exceeded 30 seconds")
        readable, _, _ = select.select([read_fd], [], [], 0)
        if readable:
            output.extend(os.read(read_fd, 1 << 20))
        time.sleep(0.01)
    os.close(read_fd)
    if status != 0:
        raise AssertionError(output.decode())
    result = json.loads(output)
    if result["fixture"] != {"nodes": 10_000, "edges": 50_000}:
        raise AssertionError(result)
    if result["hitTestP95Ms"] >= 16:
        raise AssertionError(result)
    if result["filterP95Ms"] >= 100:
        raise AssertionError(result)
