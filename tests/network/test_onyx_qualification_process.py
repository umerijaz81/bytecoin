#!/usr/bin/env python3
"""Real-process identity and isolation checks for the fixed Onyx qualification network."""

import argparse
import json
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def rpc_call(port, method):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": method, "method": method, "params": {}},
        separators=(",", ":"),
    ).encode("ascii")
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/json_rpc",
        data=body,
        headers={"Content-Type": "application/json-rpc"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        decoded = json.loads(response.read().decode("utf-8"))
    if "error" in decoded or "result" not in decoded:
        raise RuntimeError(f"{method} failed: {decoded}")
    return decoded["result"]


class Node:
    def __init__(self, binary, root, name, net, p2p_port, rpc_port, exclusive_port):
        self.name = name
        self.rpc_port = rpc_port
        data = root / f"{name}-data"
        data.mkdir()
        self.log_path = root / f"{name}.log"
        self.log = self.log_path.open("w+", encoding="utf-8")
        self.process = subprocess.Popen(
            [
                str(binary),
                f"--net={net}",
                f"--data-folder={data}",
                f"--p2p-bind-address=127.0.0.1:{p2p_port}",
                f"--bytecoind-bind-address=127.0.0.1:{rpc_port}",
                f"--exclusive-node-address=127.0.0.1:{exclusive_port}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            text=True,
        )

    def check(self):
        if self.process.poll() is not None:
            self.log.flush()
            self.log.seek(0)
            raise RuntimeError(
                f"{self.name} exited unexpectedly ({self.process.returncode})\n{self.log.read()}"
            )

    def status(self):
        return rpc_call(self.rpc_port, "get_status")

    def statistics(self):
        return rpc_call(self.rpc_port, "get_statistics")

    def read_log(self):
        self.log.flush()
        self.log.seek(0)
        return self.log.read()

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log.close()


def wait_until(description, predicate, nodes, timeout=30):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        for node in nodes:
            node.check()
        try:
            value = predicate()
            if value:
                return value
        except (OSError, RuntimeError, urllib.error.URLError) as error:
            last_error = error
        time.sleep(0.1)
    suffix = f": {last_error}" if last_error else ""
    raise RuntimeError(f"timed out waiting for {description}{suffix}")


def connected(statistics):
    return len(statistics.get("connected_peers", [])) > 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bytecoind", required=True, type=pathlib.Path)
    args = parser.parse_args()
    binary = args.bytecoind.resolve()
    if not binary.is_file():
        parser.error(f"bytecoind does not exist: {binary}")

    with tempfile.TemporaryDirectory(prefix="bytecoin-onyx-net-") as temporary:
        root = pathlib.Path(temporary)
        onyx_a_p2p, onyx_a_rpc = unused_port(), unused_port()
        onyx_b_p2p, onyx_b_rpc = unused_port(), unused_port()
        foreign_p2p, foreign_rpc = unused_port(), unused_port()
        nodes = []
        try:
            onyx_a = Node(
                binary, root, "onyx-a", "onyx", onyx_a_p2p, onyx_a_rpc, onyx_b_p2p
            )
            nodes.append(onyx_a)
            onyx_b = Node(
                binary, root, "onyx-b", "onyx", onyx_b_p2p, onyx_b_rpc, onyx_a_p2p
            )
            nodes.append(onyx_b)

            wait_until("Onyx node A RPC", onyx_a.status, nodes)
            wait_until("Onyx node B RPC", onyx_b.status, nodes)
            stats_a = onyx_a.statistics()
            stats_b = onyx_b.statistics()
            if stats_a.get("net") != "onyx" or stats_b.get("net") != "onyx":
                raise RuntimeError(f"wrong network identity: {stats_a!r} / {stats_b!r}")
            genesis_a = stats_a.get("genesis_block_hash")
            genesis_b = stats_b.get("genesis_block_hash")
            if not genesis_a or genesis_a != genesis_b or genesis_a == "0" * 64:
                raise RuntimeError(f"qualification genesis mismatch: {genesis_a!r} / {genesis_b!r}")

            wait_until(
                "same-network P2P connection",
                lambda: connected(onyx_a.statistics()) and connected(onyx_b.statistics()),
                nodes,
            )
            print(f"two Onyx processes share fixed genesis {genesis_a} and connect successfully")

            foreign = Node(
                binary,
                root,
                "foreign-testnet",
                "test",
                foreign_p2p,
                foreign_rpc,
                onyx_a_p2p,
            )
            nodes.append(foreign)
            wait_until("foreign testnet RPC", foreign.status, nodes)
            time.sleep(2)
            foreign.check()
            foreign_stats = foreign.statistics()
            if foreign_stats.get("net") != "test":
                raise RuntimeError(f"foreign control started on wrong network: {foreign_stats!r}")
            if foreign_stats.get("genesis_block_hash") == genesis_a:
                raise RuntimeError("Onyx qualification genesis aliases testnet")
            if connected(foreign_stats):
                raise RuntimeError("foreign-network process connected to the Onyx qualification network")
            print("testnet process was rejected by the Onyx P2P identity/genesis boundary")
        except Exception:
            for node in nodes:
                print(f"\n--- {node.name} log ---\n{node.read_log()}")
            raise
        finally:
            for node in reversed(nodes):
                node.stop()


if __name__ == "__main__":
    main()
