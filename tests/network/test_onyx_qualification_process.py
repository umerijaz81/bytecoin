#!/usr/bin/env python3
"""Real-process identity and isolation checks for the fixed Onyx qualification network."""

import argparse
import base64
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
WALLET_PASSWORD = "onyx-local-qualification-password"
RECOVERY_PASSWORD = "onyx-local-recovery-password"
WALLET_AUTH = "onyx-local:qualification-auth"


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def rpc_response(port, method, params=None, authorization=None):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": method, "method": method, "params": params or {}},
        separators=(",", ":"),
    ).encode("ascii")
    headers = {"Content-Type": "application/json-rpc"}
    if authorization:
        token = base64.b64encode(authorization.encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {token}"
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/json_rpc",
        data=body,
        headers=headers,
        method="POST",
    )
    # Real Halo2 proving is intentionally exercised by this harness and can exceed the short
    # control-plane timeout used by the non-proving RPC calls on slower CI workers.
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.loads(response.read().decode("utf-8"))


def rpc_call(port, method, params=None, authorization=None):
    decoded = rpc_response(port, method, params, authorization)
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


class WalletProcess:
    def __init__(self, binary, root, wallet_file, data, rpc_port, node_rpc_port, password):
        self.name = "qualification-wallet"
        self.rpc_port = rpc_port
        self.log_path = root / "qualification-wallet.log"
        self.log = self.log_path.open("w+", encoding="utf-8")
        auth_file = root / "walletd.auth"
        if not auth_file.exists():
            auth_file.write_text(WALLET_AUTH + "\n", encoding="utf-8")
            auth_file.chmod(0o600)
        self.process = subprocess.Popen(
            [
                str(binary),
                "--net=onyx",
                f"--data-folder={data}",
                f"--wallet-file={wallet_file}",
                f"--walletd-http-auth-file={auth_file}",
                f"--walletd-bind-address=127.0.0.1:{rpc_port}",
                f"--bytecoind-remote-address=127.0.0.1:{node_rpc_port}",
            ],
            stdin=subprocess.PIPE,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.process.stdin.write(password + "\n")
        self.process.stdin.close()

    def check(self):
        if self.process.poll() is not None:
            raise RuntimeError(
                f"walletd exited unexpectedly ({self.process.returncode})\n{self.read_log()}"
            )

    def status(self):
        return rpc_call(self.rpc_port, "get_status", authorization=WALLET_AUTH)

    def call(self, method, params=None):
        return rpc_call(self.rpc_port, method, params, authorization=WALLET_AUTH)

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


def create_wallet(walletd, root):
    # A legacy wallet is the qualification migration source: it scans the version-1 coinbase
    # outputs that V7 blocks carry (an amethyst wallet's unlinkable output handler cannot see
    # them), and it still derives an Onyx identity from its seed.
    wallet_file = root / "qualification.wallet"
    wallet_data = root / "wallet-data"
    wallet_data.mkdir()
    creation_input = f"{WALLET_PASSWORD}\n{WALLET_PASSWORD}\n"
    result = subprocess.run(
        [
            str(walletd),
            "--net=onyx",
            f"--data-folder={wallet_data}",
            f"--wallet-file={wallet_file}",
            "--create-wallet",
            "--wallet-type=legacy",
            "--creation-timestamp=0",
        ],
        input=creation_input,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Onyx wallet creation failed\n{result.stdout}\n{result.stderr}")
    return wallet_file, wallet_data


def recover_wallet(walletd, root, wallet_file, wallet_data):
    backup_data = root / "recovered-wallet-data"
    backup_data.mkdir()
    result = subprocess.run(
        [
            str(walletd),
            "--net=onyx",
            f"--data-folder={wallet_data}",
            f"--wallet-file={wallet_file}",
            f"--backup-wallet-data={backup_data}",
            "--set-password",
        ],
        input=f"{WALLET_PASSWORD}\n{RECOVERY_PASSWORD}\n{RECOVERY_PASSWORD}\n",
        capture_output=True,
        text=True,
        timeout=45,
    )
    if result.returncode != 0 or "finished successfully" not in result.stdout:
        raise RuntimeError(f"Onyx wallet backup/recovery failed\n{result.stdout}\n{result.stderr}")
    recovered_wallet = backup_data / wallet_file.name
    if not recovered_wallet.is_file():
        raise RuntimeError("Onyx wallet backup omitted the encrypted wallet file")
    old_password = subprocess.run(
        [
            str(walletd),
            "--net=onyx",
            f"--data-folder={backup_data}",
            f"--wallet-file={recovered_wallet}",
            "--export-keys",
        ],
        input=WALLET_PASSWORD + "\n",
        capture_output=True,
        text=True,
        timeout=20,
    )
    if old_password.returncode == 0:
        raise RuntimeError("recovered Onyx wallet accepted its superseded password")
    return recovered_wallet, backup_data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bytecoind", required=True, type=pathlib.Path)
    parser.add_argument("--minerd", required=True, type=pathlib.Path)
    parser.add_argument("--walletd", required=True, type=pathlib.Path)
    parser.add_argument("--report", type=pathlib.Path)
    parser.add_argument("--revision", default=os.environ.get("GITHUB_SHA", "unbound-local-run"))
    args = parser.parse_args()
    binary = args.bytecoind.resolve()
    minerd = args.minerd.resolve()
    walletd = args.walletd.resolve()
    if not binary.is_file():
        parser.error(f"bytecoind does not exist: {binary}")
    if not minerd.is_file():
        parser.error(f"minerd does not exist: {minerd}")
    if not walletd.is_file():
        parser.error(f"walletd does not exist: {walletd}")

    with tempfile.TemporaryDirectory(prefix="bytecoin-onyx-net-") as temporary:
        root = pathlib.Path(temporary)
        onyx_a_p2p, onyx_a_rpc = unused_port(), unused_port()
        onyx_b_p2p, onyx_b_rpc = unused_port(), unused_port()
        onyx_c_p2p, onyx_c_rpc = unused_port(), unused_port()
        foreign_p2p, foreign_rpc = unused_port(), unused_port()
        wallet_rpc = unused_port()
        nodes = []
        wallet = None
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

            wallet_file, wallet_data = create_wallet(walletd, root)
            wallet = WalletProcess(
                walletd,
                root,
                wallet_file,
                wallet_data,
                wallet_rpc,
                onyx_b_rpc,
                WALLET_PASSWORD,
            )
            wait_until("Onyx wallet RPC", wallet.status, nodes + [wallet])
            initial_addresses = wallet.call("get_addresses")["addresses"]
            initial_onyx_status = wallet.call("get_onyx_status")
            if len(initial_addresses) != 1 or not initial_onyx_status.get("address"):
                raise RuntimeError(
                    f"Onyx wallet identity is incomplete: {initial_addresses!r} "
                    f"{initial_onyx_status!r}"
                )
            wallet.stop()
            wallet = None

            mine_blocks(minerd, root, "branch-a", onyx_a_rpc, MINING_ADDRESS_A, 2)
            # Onyx blocks are V7 from height 1, and consensus only accepts version-1 coinbase
            # transactions in V7 blocks (validate_tx_semantic), so the legacy wallet address
            # receives a v1 coinbase that its own consensus accepts and the wallet scans.
            mine_blocks(minerd, root, "branch-b", onyx_b_rpc, initial_addresses[0], 3)
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

            wallet = WalletProcess(
                walletd,
                root,
                wallet_file,
                wallet_data,
                wallet_rpc,
                onyx_a_rpc,
                WALLET_PASSWORD,
            )
            wait_until(
                "wallet synchronization after node A reorganization",
                lambda: wallet.status()["top_block_height"] >= final_height,
                nodes + [wallet],
                timeout=60,
            )
            pre_recovery_addresses = wallet.call("get_addresses")["addresses"]
            pre_recovery_onyx = wallet.call("get_onyx_status")
            pre_recovery_balance = wallet.call(
                "get_balance", {"address": "", "height_or_depth": -1}
            )
            recognized_total = (
                pre_recovery_balance["spendable"]
                + pre_recovery_balance["spendable_dust"]
                + pre_recovery_balance["locked_or_unconfirmed"]
            )
            # Amethyst-and-later coinbase outputs carry no unlock height (the unlock-time rule
            # only applies to pre-amethyst blocks), so recognized rewards are immediately
            # spendable rather than locked.
            if recognized_total <= 0 or pre_recovery_balance["spendable_outputs"] <= 0:
                raise RuntimeError(
                    f"wallet did not recognize branch-B mining rewards: {pre_recovery_balance!r}"
                )
            wallet.stop()
            wallet = None

            recovered_wallet, recovered_data = recover_wallet(
                walletd, root, wallet_file, wallet_data
            )
            wallet = WalletProcess(
                walletd,
                root,
                recovered_wallet,
                recovered_data,
                wallet_rpc,
                onyx_c_rpc,
                RECOVERY_PASSWORD,
            )
            wait_until(
                "recovered wallet synchronization through node C",
                lambda: wallet.status()["top_block_height"] >= final_height,
                nodes + [wallet],
                timeout=60,
            )
            recovered_addresses = wallet.call("get_addresses")["addresses"]
            recovered_onyx = wallet.call("get_onyx_status")
            recovered_balance = wallet.call(
                "get_balance", {"address": "", "height_or_depth": -1}
            )
            if (
                recovered_addresses != pre_recovery_addresses
                or recovered_addresses != initial_addresses
                or recovered_onyx.get("address") != pre_recovery_onyx.get("address")
                or recovered_onyx.get("address") != initial_onyx_status.get("address")
                or recovered_balance != pre_recovery_balance
            ):
                raise RuntimeError(
                    "alternate-node recovery changed wallet identity or balance: "
                    f"{recovered_addresses!r} {recovered_onyx!r} {recovered_balance!r}"
                )
            print(
                "Onyx wallet recognized mined funds and preserved legacy/Onyx identities and "
                "balance through encrypted backup, password rotation and node-C recovery"
            )

            unspents = wallet.call(
                "get_unspents",
                {"address": recovered_addresses[0], "height_or_depth": -1},
            )["spendable"]
            migration_output = next(
                (output for output in unspents if output["amount"] > 1), None
            )
            if migration_output is None:
                raise RuntimeError(f"wallet has no output suitable for migration: {unspents!r}")
            migration_fee = 1
            bridge_create = wallet.call(
                "create_onyx_bridge",
                {
                    "address": recovered_onyx["address"],
                    "legacy_amount": migration_output["amount"],
                    "fee": migration_fee,
                    "legacy_stack_index": migration_output["stack_index"],
                    "legacy_key_image": migration_output["key_image"],
                    "expiry_height": 0,
                    "memo": "local qualification migration",
                },
            )
            unsigned_bridge = bridge_create["unsigned_bridge"]
            ownership_signature = wallet.call(
                "sign_onyx_bridge", {"unsigned_bridge": unsigned_bridge}
            )["ownership_signature"]
            if len(ownership_signature) != 128:
                raise RuntimeError("wallet returned a non-canonical bridge ownership signature")
            tampered_bridge = unsigned_bridge[:-2] + (
                "00" if unsigned_bridge[-2:] != "00" else "01"
            )
            tampered_response = rpc_response(
                wallet.rpc_port,
                "sign_onyx_bridge",
                {"unsigned_bridge": tampered_bridge},
                WALLET_AUTH,
            )
            if tampered_response.get("error", {}).get("code") != -32602:
                raise RuntimeError(
                    f"wallet signed or misclassified a tampered bridge: {tampered_response!r}"
                )
            finalized_bridge = wallet.call(
                "finalize_onyx_bridge",
                {
                    "unsigned_bridge": unsigned_bridge,
                    "ownership_signature": ownership_signature,
                },
            )
            rpc_call(
                onyx_c.rpc_port,
                "send_transaction",
                {"binary_transaction": finalized_bridge["binary_transaction"]},
            )
            mine_blocks(minerd, root, "bridge-confirmation", onyx_c_rpc, MINING_ADDRESS_A, 1)
            bridge_height = final_height + 1
            wait_until(
                "confirmed bridge convergence",
                lambda: all(
                    node.status()["top_block_height"] >= bridge_height
                    for node in (onyx_a, onyx_b, onyx_c)
                )
                and len(
                    {
                        node.status()["top_block_hash"]
                        for node in (onyx_a, onyx_b, onyx_c)
                    }
                )
                == 1,
                nodes + [wallet],
                timeout=60,
            )
            wait_until(
                "wallet bridge recognition",
                lambda: wallet.status()["top_block_height"] >= bridge_height
                and wallet.call("get_onyx_status")["balance"]
                == migration_output["amount"] - migration_fee,
                nodes + [wallet],
                timeout=60,
            )
            replay_sign_response = rpc_response(
                wallet.rpc_port,
                "sign_onyx_bridge",
                {"unsigned_bridge": unsigned_bridge},
                WALLET_AUTH,
            )
            if replay_sign_response.get("error", {}).get("code") != -32602:
                raise RuntimeError(
                    f"wallet re-signed a consumed bridge output: {replay_sign_response!r}"
                )
            post_bridge_balance = wallet.call(
                "get_balance", {"address": "", "height_or_depth": -1}
            )
            remaining_legacy_total = (
                post_bridge_balance["spendable"]
                + post_bridge_balance["spendable_dust"]
                + post_bridge_balance["locked_or_unconfirmed"]
            )
            if remaining_legacy_total != recognized_total - migration_output["amount"]:
                raise RuntimeError(
                    "confirmed bridge did not consume the exact legacy wallet output: "
                    f"before={recognized_total} migrated={migration_output['amount']} "
                    f"after={post_bridge_balance!r}"
                )
            audits = [
                rpc_call(node.rpc_port, "get_onyx_supply_audit")
                for node in (onyx_a, onyx_b, onyx_c)
            ]
            if audits[1:] != audits[:-1]:
                raise RuntimeError(f"post-bridge supply audits diverged: {audits!r}")
            expected_shielded = migration_output["amount"] - migration_fee
            if (
                audits[0].get("total_bridged") != migration_output["amount"]
                or audits[0].get("total_fees") != migration_fee
                or audits[0].get("circulating_supply") != expected_shielded
                or audits[0].get("commitment_count") != 1
            ):
                raise RuntimeError(f"bridge supply conservation failed: {audits[0]!r}")
            final_height = bridge_height
            final_statuses = [onyx_a.status(), onyx_b.status(), onyx_c.status()]
            final_tip = final_statuses[0]["top_block_hash"]
            print(
                "wallet signed and confirmed a real legacy-to-Onyx migration with exact "
                "supply conservation and consumed-output replay rejection"
            )

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
                    "wallet_mined_fund_recognition": "passed",
                    "wallet_alternate_node_recovery": "passed",
                    "legacy_to_onyx_migration": "passed",
                    "bridge_tamper_rejection": "passed",
                    "bridge_replay_rejection": "passed",
                    "foreign_network_rejection": "passed",
                },
                "final_supply_audit": audits[0],
                "wallet": {
                    "legacy_address_count": len(recovered_addresses),
                    "onyx_address": recovered_onyx["address"],
                    "recognized_total": recognized_total,
                    "spendable_outputs": recovered_balance["spendable_outputs"],
                    "migrated_legacy_amount": migration_output["amount"],
                    "migration_fee": migration_fee,
                    "shielded_balance": expected_shielded,
                    "remaining_legacy_total": remaining_legacy_total,
                },
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
            if wallet is not None:
                print(f"\n--- {wallet.name} log ---\n{wallet.read_log()}")
            raise
        finally:
            if wallet is not None:
                wallet.stop()
            for node in reversed(nodes):
                node.stop()


if __name__ == "__main__":
    main()
