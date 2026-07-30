#!/usr/bin/env python3
"""Real-process identity and isolation checks for the fixed Onyx qualification network."""

import argparse
import datetime
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


MINING_ADDRESS_A = (
    "21mQ7KPdmLbjfpg3Coayi4hZzAEgjeL87QXGeDTHahKeJsvKHc6DoprAJmqU"
    "cLhWTUXtxCL6rQFSwEUe6NZdEoqZNpSq1iC"
)
MINING_ADDRESS_B = (
    "24xTx43fFtNBUn5f6Fj1wC7y8JsbD4N1XS2s3Q8HzWxtfvERccTPX6e5ua1"
    "mf55Wm7Z4MiaWT7LPeiBxPtD8kU9V7z3kuex"
)


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def rpc_response(port, method, params=None):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": method, "method": method, "params": params or {}},
        separators=(",", ":"),
    ).encode("ascii")
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/json_rpc",
        data=body,
        headers={"Content-Type": "application/json-rpc"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def rpc_call(port, method, params=None):
    decoded = rpc_response(port, method, params)
    if "error" in decoded or "result" not in decoded:
        raise RuntimeError(f"{method} failed: {decoded}")
    return decoded["result"]


class Node:
    def __init__(
        self, binary, root, name, net, p2p_port, rpc_port, exclusive_port=None, data=None
    ):
        self.name = name
        self.rpc_port = rpc_port
        self.data = data or root / f"{name}-data"
        self.data.mkdir(exist_ok=True)
        self.log_path = root / f"{name}.log"
        self.log = self.log_path.open("w+", encoding="utf-8")
        command = [
            str(binary),
            f"--net={net}",
            f"--data-folder={self.data}",
            f"--p2p-bind-address=127.0.0.1:{p2p_port}",
            f"--bytecoind-bind-address=127.0.0.1:{rpc_port}",
        ]
        if exclusive_port is not None:
            command.append(f"--exclusive-node-address=127.0.0.1:{exclusive_port}")
        self.process = subprocess.Popen(
            command,
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


def mine_blocks(minerd, root, name, rpc_port, wallet_address, count):
    data = root / f"{name}-miner-data"
    data.mkdir()
    result = subprocess.run(
        [
            str(minerd),
            "--net=onyx",
            f"--data-folder={data}",
            f"--bytecoind-address=127.0.0.1:{rpc_port}",
            f"--wallet-address={wallet_address}",
            "--threads=1",
            f"--limit={count}",
        ],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode != 0 or result.stdout.count("Block submitted") < count:
        raise RuntimeError(
            f"mining {count} Onyx qualification blocks failed\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def assert_malformed_v7_rejected(node):
    response = rpc_response(node.rpc_port, "send_transaction", {"binary_transaction": "07"})
    error = response.get("error", {})
    if error.get("code") != -101:
        raise RuntimeError(f"{node.name} accepted or misclassified truncated V7 bytes: {response}")
    node.check()
    node.status()


def canonical_utc_now():
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bytecoind", required=True, type=pathlib.Path)
    parser.add_argument("--minerd", required=True, type=pathlib.Path)
    parser.add_argument("--report", type=pathlib.Path)
    parser.add_argument("--revision", default=os.environ.get("GITHUB_SHA", "unbound-local-run"))
    args = parser.parse_args()
    binary = args.bytecoind.resolve()
    minerd = args.minerd.resolve()
    if not binary.is_file():
        parser.error(f"bytecoind does not exist: {binary}")
    if not minerd.is_file():
        parser.error(f"minerd does not exist: {minerd}")

    with tempfile.TemporaryDirectory(prefix="bytecoin-onyx-net-") as temporary:
        root = pathlib.Path(temporary)
        onyx_a_p2p, onyx_a_rpc = unused_port(), unused_port()
        onyx_b_p2p, onyx_b_rpc = unused_port(), unused_port()
        onyx_c_p2p, onyx_c_rpc = unused_port(), unused_port()
        foreign_p2p, foreign_rpc = unused_port(), unused_port()
        nodes = []
        try:
            onyx_a = Node(binary, root, "onyx-a-isolated", "onyx", onyx_a_p2p, onyx_a_rpc)
            nodes.append(onyx_a)
            onyx_b = Node(binary, root, "onyx-b-isolated", "onyx", onyx_b_p2p, onyx_b_rpc)
            nodes.append(onyx_b)
            onyx_c = Node(binary, root, "onyx-c-isolated", "onyx", onyx_c_p2p, onyx_c_rpc)
            nodes.append(onyx_c)

            wait_until("Onyx node A RPC", onyx_a.status, nodes)
            wait_until("Onyx node B RPC", onyx_b.status, nodes)
            wait_until("Onyx node C RPC", onyx_c.status, nodes)
            stats_a = onyx_a.statistics()
            stats_b = onyx_b.statistics()
            stats_c = onyx_c.statistics()
            statistics = [stats_a, stats_b, stats_c]
            if any(stats.get("net") != "onyx" for stats in statistics):
                raise RuntimeError(f"wrong network identity: {statistics!r}")
            geneses = {stats.get("genesis_block_hash") for stats in statistics}
            if len(geneses) != 1 or not next(iter(geneses)) or next(iter(geneses)) == "0" * 64:
                raise RuntimeError(f"qualification genesis mismatch: {geneses!r}")
            genesis = next(iter(geneses))
            if any(connected(stats) for stats in statistics):
                raise RuntimeError("supposedly isolated qualification branches connected prematurely")

            mine_blocks(minerd, root, "branch-a", onyx_a_rpc, MINING_ADDRESS_A, 2)
            mine_blocks(minerd, root, "branch-b", onyx_b_rpc, MINING_ADDRESS_B, 3)
            wait_until(
                "isolated branch A height",
                lambda: onyx_a.status()["top_block_height"] >= 2,
                nodes,
            )
            wait_until(
                "isolated branch B height",
                lambda: onyx_b.status()["top_block_height"] >= 3,
                nodes,
            )
            branch_a_tip = onyx_a.status()["top_block_hash"]
            branch_b_tip = onyx_b.status()["top_block_hash"]
            if branch_a_tip == branch_b_tip:
                raise RuntimeError("independent qualification branches did not diverge")

            onyx_a_data = onyx_a.data
            onyx_c_data = onyx_c.data
            onyx_a.stop()
            onyx_c.stop()
            nodes.remove(onyx_a)
            nodes.remove(onyx_c)
            onyx_a = Node(
                binary,
                root,
                "onyx-a-rejoin",
                "onyx",
                onyx_a_p2p,
                onyx_a_rpc,
                onyx_b_p2p,
                onyx_a_data,
            )
            nodes.append(onyx_a)
            onyx_c = Node(
                binary,
                root,
                "onyx-c-rejoin",
                "onyx",
                onyx_c_p2p,
                onyx_c_rpc,
                onyx_b_p2p,
                onyx_c_data,
            )
            nodes.append(onyx_c)
            wait_until(
                "three-node longer-branch convergence",
                lambda: (
                    onyx_a.status()["top_block_height"] >= 3
                    and onyx_b.status()["top_block_height"] >= 3
                    and onyx_c.status()["top_block_height"] >= 3
                    and len(
                        {
                            onyx_a.status()["top_block_hash"],
                            onyx_b.status()["top_block_hash"],
                            onyx_c.status()["top_block_hash"],
                        }
                    )
                    == 1
                ),
                nodes,
                timeout=60,
            )
            final_statuses = [onyx_a.status(), onyx_b.status(), onyx_c.status()]
            final_statistics = [
                onyx_a.statistics(),
                onyx_b.statistics(),
                onyx_c.statistics(),
            ]
            final_tip = final_statuses[0]["top_block_hash"]
            final_height = final_statuses[0]["top_block_height"]
            if any(
                stats.get("net") != "onyx" or stats.get("genesis_block_hash") != genesis
                for stats in final_statistics
            ):
                raise RuntimeError(f"network identity changed after restart: {final_statistics!r}")
            if len({str(stats.get("peer_id")) for stats in final_statistics}) != 3:
                raise RuntimeError(f"qualification node peer identities are not distinct: {final_statistics!r}")
            if final_tip != branch_b_tip or final_tip == branch_a_tip:
                raise RuntimeError(
                    f"nodes did not reorganize to the longer branch: "
                    f"A={branch_a_tip} B={branch_b_tip} final={final_tip}"
                )
            audits = [
                rpc_call(node.rpc_port, "get_onyx_supply_audit")
                for node in (onyx_a, onyx_b, onyx_c)
            ]
            if audits[1:] != audits[:-1]:
                raise RuntimeError(f"post-reorg supply audits diverged: {audits!r}")
            if audits[0].get("block_height") != final_height:
                raise RuntimeError(
                    f"supply audit is not bound to the converged tip height: {audits[0]!r}"
                )
            for node in (onyx_a, onyx_b, onyx_c):
                assert_malformed_v7_rejected(node)
            print(
                f"three Onyx nodes converged after a real height-{final_height} reorganization "
                f"with exact supply-audit equality"
            )
            print("all three nodes rejected a truncated V7 transaction and remained live")

            foreign = Node(
                binary,
                root,
                "foreign-testnet",
                "test",
                foreign_p2p,
                foreign_rpc,
                onyx_b_p2p,
            )
            nodes.append(foreign)
            wait_until("foreign testnet RPC", foreign.status, nodes)
            time.sleep(2)
            foreign.check()
            foreign_stats = foreign.statistics()
            if foreign_stats.get("net") != "test":
                raise RuntimeError(f"foreign control started on wrong network: {foreign_stats!r}")
            if foreign_stats.get("genesis_block_hash") == genesis:
                raise RuntimeError("Onyx qualification genesis aliases testnet")
            if connected(foreign_stats):
                raise RuntimeError("foreign-network process connected to the Onyx qualification network")
            print("testnet process was rejected by the Onyx P2P identity/genesis boundary")

            report = {
                "schema": "bytecoin-onyx-local-qualification-v1",
                "qualification_scope": "local-ci-not-release-evidence",
                "revision": args.revision,
                "generated_at": canonical_utc_now(),
                "network": "onyx",
                "genesis_block_hash": genesis,
                "node_count": 3,
                "nodes": [
                    {
                        "identity": f"local-node-{name}",
                        "peer_id": str(stats["peer_id"]),
                        "final_height": status["top_block_height"],
                        "final_block_hash": status["top_block_hash"],
                        "supply_audit": audit,
                    }
                    for name, stats, status, audit in zip(
                        ("a", "b", "c"),
                        final_statistics,
                        final_statuses,
                        audits,
                    )
                ],
                "branch_a_height": 2,
                "branch_a_tip": branch_a_tip,
                "branch_b_height": 3,
                "branch_b_tip": branch_b_tip,
                "final_height": final_height,
                "final_block_hash": final_tip,
                "scenarios": {
                    "longer_branch_reorganization": "passed",
                    "supply_audit_convergence": "passed",
                    "truncated_v7_rejection": "passed",
                    "foreign_network_rejection": "passed",
                },
                "final_supply_audit": audits[0],
            }
            if args.report:
                report_path = args.report.resolve()
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(
                    json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
                print(f"wrote non-release local qualification report to {report_path}")
        except Exception:
            for node in nodes:
                print(f"\n--- {node.name} log ---\n{node.read_log()}")
            raise
        finally:
            for node in reversed(nodes):
                node.stop()


if __name__ == "__main__":
    main()
