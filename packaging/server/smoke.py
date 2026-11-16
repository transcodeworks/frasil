#!/usr/bin/env python3
"""Test an isolated Compose deployment of frasil-relay. Requires Python 3 and
Docker Compose.

Run from any directory. DOCKER_CONTEXT selects a daemon when needed. The test
builds the image by default; --no-build reuses an image already built. It
starts the peer on a free loopback port, checks its health, its discovery
document, its user and its settings, restarts it, and checks that its iroh
endpoint, whose key lives in the data volume, survived. It removes only the
uniquely named containers, network and data volume it creates.
"""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import urllib.request
import uuid


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()
    project = "frasil-check-" + uuid.uuid4().hex[:12]
    port = free_port(socket.SOCK_STREAM)
    env = dict(
        os.environ,
        FRASIL_PORT=str(port),
        FRASIL_IROH_PORT=str(free_port(socket.SOCK_DGRAM)),
        FRASIL_ORIGIN=f"http://127.0.0.1:{port}",
    )
    compose_file = str(Path(__file__).with_name("compose.yaml").resolve())
    base = ["docker", "compose", "-p", project, "-f", compose_file]

    def compose(*arguments):
        result = subprocess.run(
            base + list(arguments), env=env, capture_output=True, text=True, timeout=1800
        )
        if result.returncode:
            raise RuntimeError(result.stderr or result.stdout)
        return result.stdout.strip()

    def get(path):
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=15) as response:
            return response.read()

    try:
        if not args.no_build:
            compose("build", "relay")
        compose("up", "-d", "--wait", "--wait-timeout", "90")
        check(get("/healthz") == b"ok", "Health")
        discovery = json.loads(get("/.well-known/frasil"))
        check(discovery["frasil"] == 1, "Protocol 1 discovery")
        check(discovery["services"], "Services listed")
        check(discovery["limits"]["max_frame_bytes"] > 0, "Limits listed")
        endpoint = discovery["iroh"]["endpoint"]
        check(len(endpoint) == 64, "iroh endpoint")
        check(compose("exec", "-T", "relay", "id", "-u") == "10001", "Non-root service")
        settings = compose("exec", "-T", "relay", "frasil-relay", "check")
        check('data_dir: "/data"' in settings, "Data in /data")
        compose("restart", "relay")
        compose("up", "-d", "--wait", "--wait-timeout", "90")
        again = json.loads(get("/.well-known/frasil"))
        check(again["iroh"]["endpoint"] == endpoint, "The iroh key survives a restart")
        print(
            "Compose smoke passed: health, discovery, non-root user, settings, "
            "and the data volume across a restart."
        )
    finally:
        compose("down", "--volumes", "--remove-orphans")
        print("Removed the smoke test's temporary containers, network and volume.")


if __name__ == "__main__":
    main()
