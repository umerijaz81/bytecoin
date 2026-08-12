#!/usr/bin/env python3
"""Real-process identity and isolation checks for the fixed Onyx qualification network."""

import argparse
import base64
import contextlib
import datetime
import json
import os
import pathlib
import sqlite3
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
MAX_PENDING_PROGRAM_CONFLICT_SECONDS = 30.0
WALLET_AUTH = "onyx-local:qualification-auth"


def canonical_field(value):
    return int(value).to_bytes(32, "little").hex()


def encode_varint(value):
    encoded = bytearray()
    remaining = int(value)
    while remaining >= 0x80:
        encoded.append((remaining & 0x7F) | 0x80)
        remaining >>= 7
    encoded.append(remaining)
    return bytes(encoded)


def standard_application(kind, first, second, *suffix):
    return (
        bytes((1, kind))
        + bytes.fromhex(first)
        + bytes.fromhex(second)
        + b"".join(encode_varint(value) for value in suffix)
    ).hex()


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
    # Real Halo2 proving and independent node verification are intentionally exercised by this
    # harness. Cold token-program artifact generation can take substantially longer than ordinary
    # control-plane requests on qualification workers.
    with urllib.request.urlopen(request, timeout=1800) as response:
        return json.loads(response.read().decode("utf-8"))


def rpc_call(port, method, params=None, authorization=None):
    decoded = rpc_response(port, method, params, authorization)
    if "error" in decoded or "result" not in decoded:
        raise RuntimeError(f"{method} failed: {decoded}")
    return decoded["result"]


class Node:
    def __init__(
        self,
        binary,
        root,
        name,
        net,
        p2p_port,
        rpc_port,
        exclusive_port=None,
        data=None,
        extra_args=None,
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
        command.extend(extra_args or ())
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
    def __init__(
        self,
        binary,
        root,
        wallet_file,
        data,
        rpc_port,
        node_rpc_port,
        password,
        name="qualification-wallet",
    ):
        self.name = name
        self.rpc_port = rpc_port
        self.log_path = root / f"{name}.log"
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


def transaction_known(node, transaction_hash):
    response = rpc_response(
        node.rpc_port, "get_raw_transaction", {"hash": transaction_hash}
    )
    if "result" in response:
        return True
    if response.get("error", {}).get("code") == -5:
        return False
    raise RuntimeError(
        f"{node.name} returned an unexpected transaction lookup response: {response!r}"
    )


def mine_blocks(minerd, root, name, rpc_port, wallet_address, count, timeout=180):
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
        timeout=timeout,
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


def create_wallet(walletd, root, prefix="qualification"):
    # A legacy wallet is the qualification migration source: it scans the version-1 coinbase
    # outputs that V7 blocks carry (an amethyst wallet's unlinkable output handler cannot see
    # them), and it still derives an Onyx identity from its seed.
    wallet_file = root / f"{prefix}.wallet"
    wallet_data = root / f"{prefix}-wallet-data"
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
        rollback_p2p, rollback_rpc = unused_port(), unused_port()
        rollback_isolation_port = unused_port()
        foreign_p2p, foreign_rpc = unused_port(), unused_port()
        wallet_rpc = unused_port()
        receiver_wallet_rpc = unused_port()
        nodes = []
        wallet = None
        receiver_wallet = None
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

            receiver_file, receiver_data = create_wallet(
                walletd, root, prefix="shielded-receiver"
            )
            receiver_wallet = WalletProcess(
                walletd,
                root,
                receiver_file,
                receiver_data,
                receiver_wallet_rpc,
                onyx_b_rpc,
                WALLET_PASSWORD,
                name="shielded-receiver-wallet",
            )
            wait_until(
                "independent shielded receiver synchronization",
                lambda: receiver_wallet.status()["top_block_height"] >= final_height,
                nodes + [wallet, receiver_wallet],
                timeout=60,
            )
            receiver_onyx = receiver_wallet.call("get_onyx_status")
            if receiver_onyx.get("balance") != 0 or not receiver_onyx.get("address"):
                raise RuntimeError(
                    f"independent shielded receiver did not start empty: {receiver_onyx!r}"
                )
            transfer_fee = 1
            transfer_amount = expected_shielded - transfer_fee
            shielded_transfer = wallet.call(
                "create_onyx_transaction",
                {
                    "address": receiver_onyx["address"],
                    "amount": transfer_amount,
                    "fee": transfer_fee,
                    "expiry_height": 0,
                    "memo": "independent receiver qualification",
                },
            )
            tampered_transaction = shielded_transfer["binary_transaction"][:-2] + (
                "00"
                if shielded_transfer["binary_transaction"][-2:] != "00"
                else "01"
            )
            tampered_transfer_response = rpc_response(
                onyx_c.rpc_port,
                "send_transaction",
                {"binary_transaction": tampered_transaction},
            )
            if "error" not in tampered_transfer_response:
                raise RuntimeError(
                    "node accepted a transfer with a tampered proof or authorization: "
                    f"{tampered_transfer_response!r}"
                )
            wallet.call(
                "send_transaction",
                {"binary_transaction": shielded_transfer["binary_transaction"]},
            )
            pending_double_spend = rpc_response(
                wallet.rpc_port,
                "create_onyx_transaction",
                {
                    "address": receiver_onyx["address"],
                    "amount": transfer_amount,
                    "fee": transfer_fee,
                    "expiry_height": 0,
                    "memo": "must be reserved",
                },
                WALLET_AUTH,
            )
            if pending_double_spend.get("error", {}).get("code") != -32602:
                raise RuntimeError(
                    f"wallet did not reserve pending shielded spends: {pending_double_spend!r}"
                )
            mine_blocks(
                minerd,
                root,
                "shielded-transfer-confirmation",
                onyx_c_rpc,
                MINING_ADDRESS_A,
                1,
            )
            transfer_height = final_height + 1
            wait_until(
                "shielded transfer convergence",
                lambda: all(
                    node.status()["top_block_height"] >= transfer_height
                    for node in (onyx_a, onyx_b, onyx_c)
                )
                and len(
                    {
                        node.status()["top_block_hash"]
                        for node in (onyx_a, onyx_b, onyx_c)
                    }
                )
                == 1,
                nodes + [wallet, receiver_wallet],
                timeout=60,
            )
            wait_until(
                "sender and receiver shielded balance recognition",
                lambda: wallet.status()["top_block_height"] >= transfer_height
                and receiver_wallet.status()["top_block_height"] >= transfer_height
                and wallet.call("get_onyx_status")["balance"] == 0
                and receiver_wallet.call("get_onyx_status")["balance"]
                == transfer_amount,
                nodes + [wallet, receiver_wallet],
                timeout=60,
            )
            replay_transfer_response = rpc_response(
                onyx_a.rpc_port,
                "send_transaction",
                {"binary_transaction": shielded_transfer["binary_transaction"]},
            )
            if "error" not in replay_transfer_response:
                raise RuntimeError(
                    f"node accepted a confirmed nullifier replay: {replay_transfer_response!r}"
                )
            audits = [
                rpc_call(node.rpc_port, "get_onyx_supply_audit")
                for node in (onyx_a, onyx_b, onyx_c)
            ]
            expected_circulating = transfer_amount
            if audits[1:] != audits[:-1] or (
                audits[0].get("total_bridged") != migration_output["amount"]
                or audits[0].get("total_fees") != migration_fee + transfer_fee
                or audits[0].get("circulating_supply") != expected_circulating
                or audits[0].get("commitment_count") != 2
            ):
                raise RuntimeError(
                    f"post-transfer supply conservation or convergence failed: {audits!r}"
                )
            final_height = transfer_height
            final_statuses = [onyx_a.status(), onyx_b.status(), onyx_c.status()]
            final_tip = final_statuses[0]["top_block_hash"]
            print(
                "independent wallets completed a real shielded transfer with pending-spend "
                "reservation, tamper/nullifier replay rejection, and exact fee accounting"
            )

            deployment_fee = 100000
            standard_deployment = receiver_wallet.call(
                "create_onyx_standard_program_deployment",
                {
                    "kind": "nft",
                    "activation_height": 0,
                    "deactivation_height": 0,
                    "fee": deployment_fee,
                    "expiry_height": 0,
                },
            )
            tampered_deployment = standard_deployment["binary_transaction"][:-2] + (
                "00"
                if standard_deployment["binary_transaction"][-2:] != "00"
                else "01"
            )
            tampered_deployment_response = rpc_response(
                onyx_a.rpc_port,
                "send_transaction",
                {"binary_transaction": tampered_deployment},
            )
            if "error" not in tampered_deployment_response:
                raise RuntimeError(
                    "node accepted a standard-program deployment with tampered proof data: "
                    f"{tampered_deployment_response!r}"
                )
            receiver_wallet.call(
                "send_transaction",
                {"binary_transaction": standard_deployment["binary_transaction"]},
            )
            pending_duplicate_deployment = rpc_response(
                receiver_wallet.rpc_port,
                "create_onyx_standard_program_deployment",
                {
                    "kind": "nft",
                    "activation_height": 0,
                    "deactivation_height": 0,
                    "fee": deployment_fee,
                    "expiry_height": 0,
                },
                WALLET_AUTH,
            )
            if pending_duplicate_deployment.get("error", {}).get("code") != -32602:
                raise RuntimeError(
                    "wallet did not reserve pending standard-program deployment spends: "
                    f"{pending_duplicate_deployment!r}"
                )
            wait_until(
                "standard-program deployment propagation",
                lambda: all(
                    transaction_known(node, standard_deployment["transaction_hash"])
                    for node in (onyx_a, onyx_b, onyx_c)
                ),
                nodes + [wallet, receiver_wallet],
                timeout=120,
            )
            mine_blocks(
                minerd,
                root,
                "standard-program-deployment-confirmation",
                onyx_a_rpc,
                MINING_ADDRESS_A,
                1,
            )
            deployment_height = final_height + 1
            wait_until(
                "standard-program deployment convergence",
                lambda: all(
                    node.status()["top_block_height"] >= deployment_height
                    for node in (onyx_a, onyx_b, onyx_c)
                )
                and len(
                    {
                        node.status()["top_block_hash"]
                        for node in (onyx_a, onyx_b, onyx_c)
                    }
                )
                == 1,
                nodes + [wallet, receiver_wallet],
                timeout=60,
            )
            post_deployment_balance = transfer_amount - deployment_fee
            wait_until(
                "standard-program deployment wallet accounting",
                lambda: receiver_wallet.status()["top_block_height"] >= deployment_height
                and receiver_wallet.call("get_onyx_status")["balance"]
                == post_deployment_balance,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            replay_deployment_response = rpc_response(
                onyx_c.rpc_port,
                "send_transaction",
                {"binary_transaction": standard_deployment["binary_transaction"]},
            )
            if "error" not in replay_deployment_response:
                raise RuntimeError(
                    "node accepted a confirmed standard-program deployment replay: "
                    f"{replay_deployment_response!r}"
                )
            audits = [
                rpc_call(node.rpc_port, "get_onyx_supply_audit")
                for node in (onyx_a, onyx_b, onyx_c)
            ]
            if audits[1:] != audits[:-1] or (
                audits[0].get("total_bridged") != migration_output["amount"]
                or audits[0].get("total_fees")
                != migration_fee + transfer_fee + deployment_fee
                or audits[0].get("circulating_supply") != post_deployment_balance
                or audits[0].get("commitment_count") != 4
                or audits[0].get("program_count") != 1
            ):
                raise RuntimeError(
                    "standard-program deployment state, supply, or convergence failed: "
                    f"{audits!r}"
                )
            final_height = deployment_height
            final_statuses = [onyx_a.status(), onyx_b.status(), onyx_c.status()]
            final_tip = final_statuses[0]["top_block_hash"]
            print(
                "independent wallet deployed a pinned NFT program with pending-spend, "
                "tamper/replay, registry, and exact supply checks"
            )

            # The default deployment activates twenty blocks after its expected inclusion. Advance
            # the real network to that boundary before constructing the first stateful call.
            activation_height = deployment_height + 20
            mine_blocks(
                minerd,
                root,
                "standard-program-activation",
                onyx_b_rpc,
                MINING_ADDRESS_A,
                activation_height - deployment_height,
            )
            wait_until(
                "standard-program activation convergence",
                lambda: all(
                    node.status()["top_block_height"] >= activation_height
                    for node in (onyx_a, onyx_b, onyx_c)
                ),
                nodes + [wallet, receiver_wallet],
                timeout=60,
            )
            wait_until(
                "standard-program activation wallet synchronization",
                lambda: receiver_wallet.status()["top_block_height"] >= activation_height,
                nodes + [wallet, receiver_wallet],
                timeout=60,
            )

            collection_id = (21).to_bytes(32, "little")
            token_id = (22).to_bytes(32, "little")
            nft_application = (
                bytes((1, 1))
                + collection_id
                + token_id
                + bytes((33, 1))
            ).hex()
            competing_nft_application = (
                bytes((1, 1))
                + collection_id
                + token_id
                + bytes((33, 2))
            ).hex()
            prior_state = "dea354729d447a92315a7730a8ffa9c2621f025a2e73cf2c794b7923939f1a00"
            next_state = "8503" + "00" * 30
            competing_next_state = "8603" + "00" * 30
            owner_witness = "22" + "00" * 31
            initial_states = [
                rpc_call(
                    node.rpc_port,
                    "get_onyx_standard_program_state",
                    {
                        "program_id": standard_deployment["program_id"],
                        "application": nft_application,
                    },
                )
                for node in (onyx_a, onyx_b, onyx_c)
            ]
            if initial_states[1:] != initial_states[:-1] or any(
                state.get("found")
                or state.get("state") != ""
                or state.get("block_height") != activation_height
                for state in initial_states
            ):
                raise RuntimeError(
                    f"initial standard-program state was not absent and converged: {initial_states!r}"
                )
            standard_call = receiver_wallet.call(
                "create_onyx_standard_program_call",
                {
                    "program_id": standard_deployment["program_id"],
                    "valid_from_height": 0,
                    "expiry_height": 0,
                    "application": nft_application,
                    "prior_state": prior_state,
                    "next_state": next_state,
                    "witness": owner_witness,
                },
            )
            tampered_call = standard_call["binary_transaction"][:-2] + (
                "00" if standard_call["binary_transaction"][-2:] != "00" else "01"
            )
            tampered_call_response = rpc_response(
                onyx_c.rpc_port,
                "send_transaction",
                {"binary_transaction": tampered_call},
            )
            if "error" not in tampered_call_response:
                raise RuntimeError(
                    "node accepted a standard-program call with tampered proof data: "
                    f"{tampered_call_response!r}"
                )
            receiver_wallet.call(
                "send_transaction",
                {"binary_transaction": standard_call["binary_transaction"]},
            )
            wait_until(
                "standard-program call propagation",
                lambda: all(
                    transaction_known(node, standard_call["transaction_hash"])
                    for node in (onyx_a, onyx_b, onyx_c)
                ),
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            competing_call = receiver_wallet.call(
                "create_onyx_standard_program_call",
                {
                    "program_id": standard_deployment["program_id"],
                    "valid_from_height": 0,
                    "expiry_height": 0,
                    "application": competing_nft_application,
                    "prior_state": prior_state,
                    "next_state": competing_next_state,
                    "witness": owner_witness,
                },
            )
            competing_call_started = time.monotonic()
            competing_call_response = rpc_response(
                onyx_b.rpc_port,
                "send_transaction",
                {"binary_transaction": competing_call["binary_transaction"]},
            )
            competing_call_elapsed = time.monotonic() - competing_call_started
            pending_conflict_precheck_seconds = {
                "stateful-nft": round(competing_call_elapsed, 6)
            }
            if competing_call_elapsed > MAX_PENDING_PROGRAM_CONFLICT_SECONDS:
                raise RuntimeError(
                    "pending standard-program state conflict reached expensive verification: "
                    f"elapsed={competing_call_elapsed:.3f}s"
                )
            if (
                transaction_known(onyx_b, competing_call["transaction_hash"])
                or not transaction_known(onyx_b, standard_call["transaction_hash"])
                or onyx_b.statistics()["transaction_pool_count"] != 1
            ):
                raise RuntimeError(
                    "node accepted two pending transitions for the same standard-program state: "
                    f"{competing_call_response!r}"
                )
            mine_blocks(
                minerd,
                root,
                "standard-program-call-confirmation",
                onyx_c_rpc,
                MINING_ADDRESS_A,
                1,
            )
            call_height = activation_height + 1
            wait_until(
                "standard-program call convergence",
                lambda: all(
                    node.status()["top_block_height"] >= call_height
                    for node in (onyx_a, onyx_b, onyx_c)
                )
                and len(
                    {
                        node.status()["top_block_hash"]
                        for node in (onyx_a, onyx_b, onyx_c)
                    }
                )
                == 1,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            wait_until(
                "standard-program call wallet accounting",
                lambda: receiver_wallet.status()["top_block_height"] >= call_height
                and receiver_wallet.call("get_onyx_status")["balance"]
                == post_deployment_balance,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            final_program_states = [
                rpc_call(
                    node.rpc_port,
                    "get_onyx_standard_program_state",
                    {
                        "program_id": standard_deployment["program_id"],
                        "application": nft_application,
                    },
                )
                for node in (onyx_a, onyx_b, onyx_c)
            ]
            if final_program_states[1:] != final_program_states[:-1] or any(
                not state.get("found")
                or state.get("state") != next_state
                or state.get("block_height") != call_height
                for state in final_program_states
            ):
                raise RuntimeError(
                    "standard-program call state did not converge to the proved commitment: "
                    f"{final_program_states!r}"
                )
            competing_state = rpc_call(
                onyx_a.rpc_port,
                "get_onyx_standard_program_state",
                {
                    "program_id": standard_deployment["program_id"],
                    "application": competing_nft_application,
                },
            )
            if not competing_state.get("found") or competing_state.get("state") != next_state:
                raise RuntimeError(
                    "mutable NFT nonce changed the stable state key: "
                    f"{competing_state!r}"
                )
            replay_call_response = rpc_response(
                onyx_a.rpc_port,
                "send_transaction",
                {"binary_transaction": standard_call["binary_transaction"]},
            )
            if "error" not in replay_call_response:
                raise RuntimeError(
                    "node accepted a confirmed standard-program call replay: "
                    f"{replay_call_response!r}"
                )
            audits = [
                rpc_call(node.rpc_port, "get_onyx_supply_audit")
                for node in (onyx_a, onyx_b, onyx_c)
            ]
            if audits[1:] != audits[:-1] or (
                audits[0].get("total_bridged") != migration_output["amount"]
                or audits[0].get("total_fees")
                != migration_fee + transfer_fee + deployment_fee
                or audits[0].get("circulating_supply") != post_deployment_balance
                or audits[0].get("commitment_count") != 5
                or audits[0].get("program_count") != 1
            ):
                raise RuntimeError(
                    f"standard-program call supply or convergence failed: {audits!r}"
                )
            final_height = call_height
            final_statuses = [onyx_a.status(), onyx_b.status(), onyx_c.status()]
            final_tip = final_statuses[0]["top_block_hash"]
            print(
                "independent wallet executed a stateful NFT call with activation, tamper, "
                "pending-conflict, stable-key, replay, state, and supply checks"
            )

            # Deploy a capped private-token program with independently pinned funding and execution
            # circuit parameters. Funding uses k=16 and token execution fits k=14; keeping the
            # parameters separate prevents
            # deployment/issuance drift if either circuit family changes later.
            token_cap = 5000
            token_metadata = "QTK/2"
            token_deployment_fee = 100000
            token_deployment = receiver_wallet.call(
                "create_onyx_program_deployment",
                {
                    "max_supply": token_cap,
                    "metadata": token_metadata,
                    "activation_height": 0,
                    "deactivation_height": 0,
                    "fee": token_deployment_fee,
                    "expiry_height": 0,
                },
            )
            tampered_token_deployment = token_deployment["binary_transaction"][:-2] + (
                "00" if token_deployment["binary_transaction"][-2:] != "00" else "01"
            )
            if "error" not in rpc_response(
                onyx_b.rpc_port,
                "send_transaction",
                {"binary_transaction": tampered_token_deployment},
            ):
                raise RuntimeError("node accepted a capped-token deployment with tampered proof data")
            receiver_wallet.call(
                "send_transaction",
                {"binary_transaction": token_deployment["binary_transaction"]},
            )
            pending_token_deployment = rpc_response(
                receiver_wallet.rpc_port,
                "create_onyx_program_deployment",
                {
                    "max_supply": token_cap,
                    "metadata": token_metadata,
                    "activation_height": 0,
                    "deactivation_height": 0,
                    "fee": token_deployment_fee,
                    "expiry_height": 0,
                },
                WALLET_AUTH,
            )
            if "error" not in pending_token_deployment:
                raise RuntimeError(
                    "wallet did not reserve capped-token deployment funding spends: "
                    f"{pending_token_deployment!r}"
                )
            wait_until(
                "capped-token deployment propagation",
                lambda: all(
                    transaction_known(node, token_deployment["transaction_hash"])
                    for node in (onyx_a, onyx_b, onyx_c)
                ),
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            mine_blocks(
                minerd,
                root,
                "capped-token-deployment-confirmation",
                onyx_a_rpc,
                MINING_ADDRESS_A,
                1,
                timeout=1800,
            )
            token_deployment_height = final_height + 1
            post_token_deployment_balance = post_deployment_balance - token_deployment_fee
            wait_until(
                "capped-token deployment convergence and wallet accounting",
                lambda: all(
                    node.status()["top_block_height"] >= token_deployment_height
                    for node in (onyx_a, onyx_b, onyx_c)
                )
                and receiver_wallet.status()["top_block_height"] >= token_deployment_height
                and receiver_wallet.call("get_onyx_status")["balance"]
                == post_token_deployment_balance,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            if "error" not in rpc_response(
                onyx_c.rpc_port,
                "send_transaction",
                {"binary_transaction": token_deployment["binary_transaction"]},
            ):
                raise RuntimeError("node accepted a confirmed capped-token deployment replay")
            token_status = receiver_wallet.call(
                "get_onyx_program_status", {"program_id": token_deployment["program_id"]}
            )
            token_activation_height = token_deployment_height + 20
            if (
                token_status["max_supply"] != token_cap
                or token_status["issued_supply"] != 0
                or token_status["remaining_supply"] != token_cap
                or token_status["next_sequence"] != 0
                or token_status["activation_height"] != token_activation_height
                or token_status["active"]
                or bytes.fromhex(token_status["metadata"]).decode("ascii") != token_metadata
            ):
                raise RuntimeError(f"capped-token program status mismatch: {token_status!r}")

            mine_blocks(
                minerd,
                root,
                "capped-token-activation",
                onyx_b_rpc,
                MINING_ADDRESS_A,
                token_activation_height - token_deployment_height,
                timeout=1800,
            )
            wait_until(
                "capped-token activation convergence",
                lambda: all(
                    node.status()["top_block_height"] >= token_activation_height
                    for node in (onyx_a, onyx_b, onyx_c)
                )
                and wallet.status()["top_block_height"] >= token_activation_height
                and receiver_wallet.status()["top_block_height"] >= token_activation_height,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            foreign_issuer = rpc_response(
                wallet.rpc_port,
                "create_onyx_token_issuance",
                {
                    "address": recovered_onyx["address"],
                    "program_id": token_deployment["program_id"],
                    "amount": 1,
                    "expiry_height": 0,
                    "memo": "foreign issuer must fail",
                },
                WALLET_AUTH,
            )
            if "error" not in foreign_issuer:
                raise RuntimeError(f"non-issuer wallet created token issuance: {foreign_issuer!r}")

            issued_amount = 1000
            issuance = receiver_wallet.call(
                "create_onyx_token_issuance",
                {
                    "address": receiver_onyx["address"],
                    "program_id": token_deployment["program_id"],
                    "amount": issued_amount,
                    "expiry_height": 0,
                    "memo": "qualification issuance sequence zero",
                },
            )
            if issuance["sequence"] != 0:
                raise RuntimeError(f"first issuance did not use sequence zero: {issuance!r}")
            tampered_issuance = issuance["binary_transaction"][:-2] + (
                "00" if issuance["binary_transaction"][-2:] != "00" else "01"
            )
            if "error" not in rpc_response(
                onyx_a.rpc_port,
                "send_transaction",
                {"binary_transaction": tampered_issuance},
            ):
                raise RuntimeError("node accepted token issuance with tampered proof data")
            receiver_wallet.call(
                "send_transaction", {"binary_transaction": issuance["binary_transaction"]}
            )
            duplicate_issuance = rpc_response(
                receiver_wallet.rpc_port,
                "create_onyx_token_issuance",
                {
                    "address": receiver_onyx["address"],
                    "program_id": token_deployment["program_id"],
                    "amount": 1,
                    "expiry_height": 0,
                    "memo": "pending sequence conflict",
                },
                WALLET_AUTH,
            )
            if "error" not in duplicate_issuance:
                raise RuntimeError(f"wallet reused a pending issuance sequence: {duplicate_issuance!r}")
            wait_until(
                "token issuance propagation",
                lambda: all(
                    transaction_known(node, issuance["transaction_hash"])
                    for node in (onyx_a, onyx_b, onyx_c)
                ),
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            mine_blocks(
                minerd,
                root,
                "token-issuance-confirmation",
                onyx_c_rpc,
                MINING_ADDRESS_A,
                1,
                timeout=1800,
            )
            issuance_height = token_activation_height + 1
            token_balance_request = {
                "program_id": token_deployment["program_id"],
                "asset_id": token_deployment["program_id"],
            }
            wait_until(
                "token issuance convergence and wallet recovery",
                lambda: all(
                    node.status()["top_block_height"] >= issuance_height
                    for node in (onyx_a, onyx_b, onyx_c)
                )
                and receiver_wallet.status()["top_block_height"] >= issuance_height
                and receiver_wallet.call("get_onyx_asset_balance", token_balance_request)["balance"]
                == issued_amount,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            issued_status = receiver_wallet.call(
                "get_onyx_program_status", {"program_id": token_deployment["program_id"]}
            )
            if (
                issued_status["issued_supply"] != issued_amount
                or issued_status["remaining_supply"] != token_cap - issued_amount
                or issued_status["next_sequence"] != 1
                or not issued_status["active"]
            ):
                raise RuntimeError(f"confirmed token issuance status mismatch: {issued_status!r}")
            if "error" not in rpc_response(
                onyx_b.rpc_port,
                "send_transaction",
                {"binary_transaction": issuance["binary_transaction"]},
            ):
                raise RuntimeError("node accepted a confirmed token issuance replay")
            zero_issuance = rpc_response(
                receiver_wallet.rpc_port,
                "create_onyx_token_issuance",
                {
                    "address": receiver_onyx["address"],
                    "program_id": token_deployment["program_id"],
                    "amount": 0,
                    "expiry_height": 0,
                    "memo": "zero must fail",
                },
                WALLET_AUTH,
            )
            over_cap_issuance = rpc_response(
                receiver_wallet.rpc_port,
                "create_onyx_token_issuance",
                {
                    "address": receiver_onyx["address"],
                    "program_id": token_deployment["program_id"],
                    "amount": token_cap,
                    "expiry_height": 0,
                    "memo": "cap must fail",
                },
                WALLET_AUTH,
            )
            if "error" not in zero_issuance or "error" not in over_cap_issuance:
                raise RuntimeError(
                    f"invalid issuance accepted: zero={zero_issuance!r} cap={over_cap_issuance!r}"
                )

            token_transfer_amount = 400
            token_transfer_fee = 1
            token_transfer = receiver_wallet.call(
                "create_onyx_token_transaction",
                {
                    "address": recovered_onyx["address"],
                    "program_id": token_deployment["program_id"],
                    "amount": token_transfer_amount,
                    "fee": token_transfer_fee,
                    "expiry_height": 0,
                    "memo": "qualified private token transfer",
                },
            )
            tampered_token_transfer = token_transfer["binary_transaction"][:-2] + (
                "00" if token_transfer["binary_transaction"][-2:] != "00" else "01"
            )
            if "error" not in rpc_response(
                onyx_c.rpc_port,
                "send_transaction",
                {"binary_transaction": tampered_token_transfer},
            ):
                raise RuntimeError("node accepted a private token transfer with tampered proof data")
            receiver_wallet.call(
                "send_transaction", {"binary_transaction": token_transfer["binary_transaction"]}
            )
            pending_token_transfer = rpc_response(
                receiver_wallet.rpc_port,
                "create_onyx_token_transaction",
                {
                    "address": recovered_onyx["address"],
                    "program_id": token_deployment["program_id"],
                    "amount": 1,
                    "fee": token_transfer_fee,
                    "expiry_height": 0,
                    "memo": "pending token spend must fail",
                },
                WALLET_AUTH,
            )
            if "error" not in pending_token_transfer:
                raise RuntimeError(
                    f"wallet reused pending token/native spends: {pending_token_transfer!r}"
                )
            wait_until(
                "private token transfer propagation",
                lambda: all(
                    transaction_known(node, token_transfer["transaction_hash"])
                    for node in (onyx_a, onyx_b, onyx_c)
                ),
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            mine_blocks(
                minerd,
                root,
                "private-token-transfer-confirmation",
                onyx_a_rpc,
                MINING_ADDRESS_A,
                1,
                timeout=1800,
            )
            token_transfer_height = issuance_height + 1
            sender_token_balance = issued_amount - token_transfer_amount
            receiver_native_balance = post_token_deployment_balance - token_transfer_fee
            wait_until(
                "private token transfer convergence and two-wallet recovery",
                lambda: all(
                    node.status()["top_block_height"] >= token_transfer_height
                    for node in (onyx_a, onyx_b, onyx_c)
                )
                and wallet.status()["top_block_height"] >= token_transfer_height
                and receiver_wallet.status()["top_block_height"] >= token_transfer_height
                and receiver_wallet.call("get_onyx_asset_balance", token_balance_request)["balance"]
                == sender_token_balance
                and wallet.call("get_onyx_asset_balance", token_balance_request)["balance"]
                == token_transfer_amount
                and receiver_wallet.call("get_onyx_status")["balance"]
                == receiver_native_balance,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            if "error" not in rpc_response(
                onyx_a.rpc_port,
                "send_transaction",
                {"binary_transaction": token_transfer["binary_transaction"]},
            ):
                raise RuntimeError("node accepted a confirmed private token transfer replay")
            audits = [
                rpc_call(node.rpc_port, "get_onyx_supply_audit")
                for node in (onyx_a, onyx_b, onyx_c)
            ]
            if audits[1:] != audits[:-1] or (
                audits[0].get("total_bridged") != migration_output["amount"]
                or audits[0].get("total_fees")
                != migration_fee
                + transfer_fee
                + deployment_fee
                + token_deployment_fee
                + token_transfer_fee
                or audits[0].get("circulating_supply") != receiver_native_balance
                or audits[0].get("commitment_count") != 11
                or audits[0].get("program_count") != 2
            ):
                raise RuntimeError(f"private-token final supply or convergence failed: {audits!r}")
            final_height = token_transfer_height
            final_statuses = [onyx_a.status(), onyx_b.status(), onyx_c.status()]
            final_tip = final_statuses[0]["top_block_hash"]
            print(
                "capped-token deployment, issuance, and private transfer passed activation, "
                "issuer/cap, tamper, pending-conflict, replay, balance, and supply checks"
            )
            private_token_issuer_native_balance = receiver_native_balance

            # Qualify the three remaining pinned stateful profiles against the real wallet, mempool,
            # block-application, scanner, and state-query paths. The values below are the canonical
            # vectors pinned by tests/onyx_compiler/test_standard_programs_v1.py.
            profile_deployment_fee = 100000
            profile_commitments = 11
            profile_program_count = 2
            profile_deployments = {}
            for profile_kind in ("vesting", "multisig", "swap"):
                deployment = receiver_wallet.call(
                    "create_onyx_standard_program_deployment",
                    {
                        "kind": profile_kind,
                        "activation_height": 0,
                        "deactivation_height": 0,
                        "fee": profile_deployment_fee,
                        "expiry_height": 0,
                    },
                )
                receiver_wallet.call(
                    "send_transaction",
                    {"binary_transaction": deployment["binary_transaction"]},
                )
                wait_until(
                    f"{profile_kind} deployment propagation",
                    lambda deployment=deployment: all(
                        transaction_known(node, deployment["transaction_hash"])
                        for node in (onyx_a, onyx_b, onyx_c)
                    ),
                    nodes + [wallet, receiver_wallet],
                    timeout=1800,
                )
                mine_blocks(
                    minerd,
                    root,
                    f"{profile_kind}-deployment-confirmation",
                    onyx_a_rpc,
                    MINING_ADDRESS_A,
                    1,
                    timeout=1800,
                )
                final_height += 1
                receiver_native_balance -= profile_deployment_fee
                profile_commitments += 2
                profile_program_count += 1
                wait_until(
                    f"{profile_kind} deployment convergence and wallet recovery",
                    lambda: all(
                        node.status()["top_block_height"] >= final_height
                        for node in (onyx_a, onyx_b, onyx_c)
                    )
                    and wallet.status()["top_block_height"] >= final_height
                    and receiver_wallet.status()["top_block_height"] >= final_height
                    and receiver_wallet.call("get_onyx_status")["balance"]
                    == receiver_native_balance,
                    nodes + [wallet, receiver_wallet],
                    timeout=1800,
                )
                audits = [
                    rpc_call(node.rpc_port, "get_onyx_supply_audit")
                    for node in (onyx_a, onyx_b, onyx_c)
                ]
                if audits[1:] != audits[:-1] or (
                    audits[0].get("total_fees")
                    != migration_fee
                    + transfer_fee
                    + deployment_fee
                    + token_deployment_fee
                    + token_transfer_fee
                    + profile_deployment_fee * (profile_program_count - 2)
                    or audits[0].get("circulating_supply") != receiver_native_balance
                    or audits[0].get("commitment_count") != profile_commitments
                    or audits[0].get("program_count") != profile_program_count
                ):
                    raise RuntimeError(
                        f"{profile_kind} deployment supply or convergence failed: {audits!r}"
                    )
                profile_deployments[profile_kind] = {
                    "program_id": deployment["program_id"],
                    "deployment_height": final_height,
                    "activation_height": final_height + 20,
                }

            profile_activation_height = max(
                entry["activation_height"] for entry in profile_deployments.values()
            )
            mine_blocks(
                minerd,
                root,
                "remaining-standard-profile-activation",
                onyx_b_rpc,
                MINING_ADDRESS_A,
                profile_activation_height - final_height,
                timeout=1800,
            )
            final_height = profile_activation_height
            wait_until(
                "remaining standard-profile activation and wallet convergence",
                lambda: all(
                    node.status()["top_block_height"] >= final_height
                    for node in (onyx_a, onyx_b, onyx_c)
                )
                and wallet.status()["top_block_height"] >= final_height
                and receiver_wallet.status()["top_block_height"] >= final_height,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )

            def expect_profile_call_error(label, parameters):
                response = rpc_response(
                    receiver_wallet.rpc_port,
                    "create_onyx_standard_program_call",
                    parameters,
                    WALLET_AUTH,
                )
                if "error" not in response:
                    raise RuntimeError(f"wallet constructed invalid {label}: {response!r}")

            confirmed_profile_transactions = {}

            def confirm_profile_call(label, parameters, expected_state, competitor=None):
                nonlocal final_height, profile_commitments, audits, final_statuses, final_tip
                initial = [
                    rpc_call(
                        node.rpc_port,
                        "get_onyx_standard_program_state",
                        {
                            "program_id": parameters["program_id"],
                            "application": parameters["application"],
                        },
                    )
                    for node in (onyx_a, onyx_b, onyx_c)
                ]
                if initial[1:] != initial[:-1] or any(state.get("found") for state in initial):
                    raise RuntimeError(f"{label} initial state was not absent: {initial!r}")
                transaction = receiver_wallet.call(
                    "create_onyx_standard_program_call", parameters
                )
                confirmed_profile_transactions[label] = transaction
                receiver_wallet.call(
                    "send_transaction",
                    {"binary_transaction": transaction["binary_transaction"]},
                )
                wait_until(
                    f"{label} propagation",
                    lambda: all(
                        transaction_known(node, transaction["transaction_hash"])
                        for node in (onyx_a, onyx_b, onyx_c)
                    ),
                    nodes + [wallet, receiver_wallet],
                    timeout=1800,
                )
                if competitor is not None:
                    competing = receiver_wallet.call(
                        "create_onyx_standard_program_call", competitor
                    )
                    competing_started = time.monotonic()
                    competing_response = rpc_response(
                        onyx_b.rpc_port,
                        "send_transaction",
                        {"binary_transaction": competing["binary_transaction"]},
                    )
                    competing_elapsed = time.monotonic() - competing_started
                    pending_conflict_precheck_seconds[label] = round(
                        competing_elapsed, 6
                    )
                    if competing_elapsed > MAX_PENDING_PROGRAM_CONFLICT_SECONDS:
                        raise RuntimeError(
                            f"pending {label} state conflict reached expensive verification: "
                            f"elapsed={competing_elapsed:.3f}s"
                        )
                    if (
                        transaction_known(onyx_b, competing["transaction_hash"])
                        or not transaction_known(onyx_b, transaction["transaction_hash"])
                        or onyx_b.statistics()["transaction_pool_count"] != 1
                    ):
                        raise RuntimeError(
                            f"node admitted competing {label} transition: {competing_response!r}"
                        )
                mine_blocks(
                    minerd,
                    root,
                    f"{label}-confirmation",
                    onyx_c_rpc,
                    MINING_ADDRESS_A,
                    1,
                    timeout=1800,
                )
                final_height += 1
                profile_commitments += 1
                wait_until(
                    f"{label} state and wallet convergence",
                    lambda: all(
                        node.status()["top_block_height"] >= final_height
                        for node in (onyx_a, onyx_b, onyx_c)
                    )
                    and wallet.status()["top_block_height"] >= final_height
                    and receiver_wallet.status()["top_block_height"] >= final_height,
                    nodes + [wallet, receiver_wallet],
                    timeout=1800,
                )
                states = [
                    rpc_call(
                        node.rpc_port,
                        "get_onyx_standard_program_state",
                        {
                            "program_id": parameters["program_id"],
                            "application": parameters["application"],
                        },
                    )
                    for node in (onyx_a, onyx_b, onyx_c)
                ]
                if states[1:] != states[:-1] or any(
                    not state.get("found")
                    or state.get("state") != expected_state
                    or state.get("block_height") != final_height
                    for state in states
                ):
                    raise RuntimeError(f"{label} state did not converge: {states!r}")
                if "error" not in rpc_response(
                    onyx_a.rpc_port,
                    "send_transaction",
                    {"binary_transaction": transaction["binary_transaction"]},
                ):
                    raise RuntimeError(f"node accepted confirmed {label} replay")
                audits = [
                    rpc_call(node.rpc_port, "get_onyx_supply_audit")
                    for node in (onyx_a, onyx_b, onyx_c)
                ]
                if audits[1:] != audits[:-1] or (
                    audits[0].get("total_fees") != 500003
                    or audits[0].get("circulating_supply") != receiver_native_balance
                    or audits[0].get("commitment_count") != profile_commitments
                    or audits[0].get("program_count") != profile_program_count
                ):
                    raise RuntimeError(f"{label} supply or convergence failed: {audits!r}")
                final_statuses = [onyx_a.status(), onyx_b.status(), onyx_c.status()]
                final_tip = final_statuses[0]["top_block_hash"]
                return {
                    "transaction_hash": transaction["transaction_hash"],
                    "call_height": final_height,
                    "application": parameters["application"],
                    "prior_state": parameters["prior_state"],
                    "next_state": expected_state,
                }

            vesting_unlock_height = final_height + 2
            vesting_application = standard_application(
                2, canonical_field(31), canonical_field(32), vesting_unlock_height
            )
            vesting_parameters = {
                "program_id": profile_deployments["vesting"]["program_id"],
                "valid_from_height": 0,
                "expiry_height": 0,
                "application": vesting_application,
                "prior_state": "8c500ced3490ef5572811134add0e7a1c217e22e9c3c97d25318c1d8f7d3413c",
                "next_state": canonical_field(902),
                "witness": canonical_field(33),
            }
            expect_profile_call_error("early vesting release", vesting_parameters)
            mine_blocks(
                minerd,
                root,
                "vesting-unlock-boundary",
                onyx_a_rpc,
                MINING_ADDRESS_A,
                1,
            )
            final_height += 1
            wait_until(
                "vesting unlock boundary convergence",
                lambda: all(
                    node.status()["top_block_height"] >= final_height
                    for node in (onyx_a, onyx_b, onyx_c)
                )
                and receiver_wallet.status()["top_block_height"] >= final_height,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            vesting_result = confirm_profile_call(
                "vesting-release", vesting_parameters, canonical_field(902)
            )

            zero_field = canonical_field(0)
            multisig_commitments = [
                "c82160714387a90d8abeae20442ac97c944ade58aa4f937c6d2e0fd279101d2f",
                "70627f0b52bf30c28c5d0a5249a5b9988fdc2b9b009ce20157cfd2b2976efa1c",
            ] + [zero_field] * 14
            multisig_approvals = [1, 1] + [0] * 14
            multisig_secrets = [51, 52] + [0] * 14
            multisig_witness = "".join(
                multisig_commitments
                + [canonical_field(value) for value in multisig_approvals]
                + [canonical_field(value) for value in multisig_secrets]
            )
            insufficient_multisig_witness = "".join(
                multisig_commitments
                + [canonical_field(value) for value in ([1, 0] + [0] * 14)]
                + [canonical_field(value) for value in ([51, 0] + [0] * 14)]
            )
            multisig_parameters = {
                "program_id": profile_deployments["multisig"]["program_id"],
                "valid_from_height": 0,
                "expiry_height": 0,
                "application": standard_application(
                    3,
                    "6c503e555962442bf542c81afca64a04a13259878adf417f2a970f649cf65c3a",
                    canonical_field(41),
                    2,
                    2,
                ),
                "prior_state": "e536882a61d34006a6cde79cad51f50151e8897337a3602078b1df6adccb7e30",
                "next_state": canonical_field(903),
                "witness": multisig_witness,
            }
            invalid_multisig_parameters = dict(multisig_parameters)
            invalid_multisig_parameters["witness"] = insufficient_multisig_witness
            expect_profile_call_error(
                "multisig authorization below threshold", invalid_multisig_parameters
            )
            multisig_result = confirm_profile_call(
                "multisig-authorization", multisig_parameters, canonical_field(903)
            )

            claim_timeout_height = final_height + 1
            swap_claim_parameters = {
                "program_id": profile_deployments["swap"]["program_id"],
                "valid_from_height": 0,
                "expiry_height": 0,
                "application": standard_application(
                    4,
                    canonical_field(61),
                    "61f9aa40c1fb7a42dc7e3355a41927b77e54c46c4d2ab64d6caf72d3e26fb33f",
                    claim_timeout_height,
                    0,
                ),
                "prior_state": "150307817ffa73f9df0517796ac95c91ab6e39b8bbb35e337143b355fa53942d",
                "next_state": canonical_field(904),
                "witness": canonical_field(62),
            }
            invalid_swap_claim = dict(swap_claim_parameters)
            invalid_swap_claim["witness"] = canonical_field(63)
            expect_profile_call_error("swap claim with wrong preimage", invalid_swap_claim)
            competing_swap_refund = dict(swap_claim_parameters)
            competing_swap_refund["application"] = standard_application(
                4,
                canonical_field(61),
                "61f9aa40c1fb7a42dc7e3355a41927b77e54c46c4d2ab64d6caf72d3e26fb33f",
                claim_timeout_height,
                1,
            )
            competing_swap_refund["next_state"] = canonical_field(905)
            competing_swap_refund["witness"] = zero_field
            swap_claim_result = confirm_profile_call(
                "swap-preimage-claim",
                swap_claim_parameters,
                canonical_field(904),
                competing_swap_refund,
            )

            refund_timeout_height = final_height + 2
            swap_refund_parameters = {
                "program_id": profile_deployments["swap"]["program_id"],
                "valid_from_height": 0,
                "expiry_height": 0,
                "application": standard_application(
                    4,
                    canonical_field(63),
                    "6c439f28a7e457913d43998a33fc039d20c814d974fc19e41b8d1565089d5111",
                    refund_timeout_height,
                    1,
                ),
                "prior_state": "dd749507333a18668d486f568f7f19d3368db588beef3052f8c62373037ffc09",
                "next_state": canonical_field(906),
                "witness": zero_field,
            }
            expect_profile_call_error("early swap refund", swap_refund_parameters)
            mine_blocks(
                minerd,
                root,
                "swap-refund-timeout-boundary",
                onyx_b_rpc,
                MINING_ADDRESS_A,
                1,
            )
            final_height += 1
            wait_until(
                "swap refund timeout convergence",
                lambda: all(
                    node.status()["top_block_height"] >= final_height
                    for node in (onyx_a, onyx_b, onyx_c)
                )
                and receiver_wallet.status()["top_block_height"] >= final_height,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            pre_refund_audit = rpc_call(onyx_c.rpc_port, "get_onyx_supply_audit")
            pre_refund_tip = onyx_c.status()["top_block_hash"]
            # get_status reports the in-memory tip, while the blockchain transaction is committed
            # on the daemon's periodic persistence timer. Wait for an explicit commit of this exact
            # boundary before asking SQLite for a backup; otherwise a perfectly consistent backup
            # can legitimately reopen one block behind the RPC-visible chain.
            wait_until(
                "durable height-78 refund boundary",
                lambda: f"db_commit started... tip_height={final_height} "
                in onyx_c.read_log(),
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            rollback_snapshot = root / "onyx-rollback-height-78-data"
            rollback_snapshot.mkdir()
            # subprocess.terminate() maps to a forceful process termination on Windows and can
            # leave the newest SQLite transaction in a rollback journal. A raw directory copy can
            # therefore reopen one block behind even though get_status reported the boundary tip.
            # SQLite's online backup API captures a transactionally consistent committed image
            # while the source node remains live.
            # sqlite3.Connection.__exit__ commits or rolls back but does not close the handle.
            # Explicit closing is required so Windows can remove the qualification directory.
            with contextlib.closing(
                sqlite3.connect(onyx_c.data / "blockchain.sqlite")
            ) as source_db:
                with contextlib.closing(
                    sqlite3.connect(rollback_snapshot / "blockchain.sqlite")
                ) as snapshot_db:
                    source_db.backup(snapshot_db)
            onyx_c_data = onyx_c.data
            onyx_c.stop()
            nodes.remove(onyx_c)
            onyx_c = Node(
                binary,
                root,
                "onyx-c-refund-confirmation",
                "onyx",
                onyx_c_p2p,
                onyx_c_rpc,
                onyx_b_p2p,
                onyx_c_data,
            )
            nodes.append(onyx_c)
            wait_until(
                "node C reopen at refund boundary",
                lambda: onyx_c.status()["top_block_height"] >= final_height
                and onyx_c.status()["top_block_hash"] == pre_refund_tip,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            swap_refund_result = confirm_profile_call(
                "swap-timeout-refund", swap_refund_parameters, canonical_field(906)
            )

            # Reopen a closed height-78 snapshot as an isolated branch, extend it past the
            # height-79 refund, and force every qualification node to undo the program call.
            # This exercises database undo, program-state rollback, commitment restoration,
            # wallet alternate-node synchronization, and mempool eligibility restoration.
            rollback_fork = Node(
                binary,
                root,
                "onyx-refund-rollback-fork",
                "onyx",
                rollback_p2p,
                rollback_rpc,
                rollback_isolation_port,
                data=rollback_snapshot,
            )
            nodes.append(rollback_fork)
            wait_until(
                "height-78 rollback fork reopen",
                lambda: rollback_fork.status()["top_block_height"] == 78
                and rollback_fork.status()["top_block_hash"] == pre_refund_tip,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            mine_blocks(
                minerd,
                root,
                "refund-rollback-longer-branch",
                rollback_rpc,
                MINING_ADDRESS_A,
                2,
                timeout=1800,
            )
            rollback_height = 80
            rollback_tip = wait_until(
                "isolated refund rollback branch height",
                lambda: (
                    rollback_fork.status()["top_block_hash"]
                    if rollback_fork.status()["top_block_height"] >= rollback_height
                    else None
                ),
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )

            primary_data = (onyx_a.data, onyx_b.data, onyx_c.data)
            for node in (onyx_a, onyx_b, onyx_c):
                node.stop()
                nodes.remove(node)
            onyx_a = Node(
                binary,
                root,
                "onyx-a-refund-rollback",
                "onyx",
                onyx_a_p2p,
                onyx_a_rpc,
                rollback_p2p,
                primary_data[0],
            )
            onyx_b = Node(
                binary,
                root,
                "onyx-b-refund-rollback",
                "onyx",
                onyx_b_p2p,
                onyx_b_rpc,
                rollback_p2p,
                primary_data[1],
            )
            onyx_c = Node(
                binary,
                root,
                "onyx-c-refund-rollback",
                "onyx",
                onyx_c_p2p,
                onyx_c_rpc,
                rollback_p2p,
                primary_data[2],
            )
            nodes.extend((onyx_a, onyx_b, onyx_c))
            wait_until(
                "refund rollback, node reopen, and wallet convergence",
                lambda: all(
                    node.status()["top_block_height"] >= rollback_height
                    and node.status()["top_block_hash"] == rollback_tip
                    for node in (onyx_a, onyx_b, onyx_c, rollback_fork)
                )
                and wallet.status()["top_block_height"] >= rollback_height
                and receiver_wallet.status()["top_block_height"] >= rollback_height
                and receiver_wallet.call("get_onyx_status")["balance"]
                == receiver_native_balance
                and receiver_wallet.call(
                    "get_onyx_asset_balance", token_balance_request
                )["balance"]
                == sender_token_balance
                and wallet.call("get_onyx_asset_balance", token_balance_request)["balance"]
                == token_transfer_amount,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            rolled_back_states = [
                rpc_call(
                    node.rpc_port,
                    "get_onyx_standard_program_state",
                    {
                        "program_id": swap_refund_parameters["program_id"],
                        "application": swap_refund_parameters["application"],
                    },
                )
                for node in (onyx_a, onyx_b, onyx_c, rollback_fork)
            ]
            if rolled_back_states[1:] != rolled_back_states[:-1] or any(
                state.get("found") for state in rolled_back_states
            ):
                raise RuntimeError(
                    f"refund program state survived rollback: {rolled_back_states!r}"
                )
            rollback_audits = [
                rpc_call(node.rpc_port, "get_onyx_supply_audit")
                for node in (onyx_a, onyx_b, onyx_c, rollback_fork)
            ]
            restored_fields = (
                "total_bridged",
                "total_fees",
                "circulating_supply",
                "commitment_count",
                "commitment_root",
                "program_count",
            )
            if rollback_audits[1:] != rollback_audits[:-1] or any(
                rollback_audits[0].get(field) != pre_refund_audit.get(field)
                for field in restored_fields
            ):
                raise RuntimeError(
                    "refund rollback did not restore the exact pre-call audit: "
                    f"before={pre_refund_audit!r} after={rollback_audits!r}"
                )

            receiver_before_alternate_reopen = receiver_wallet.call("get_onyx_status")
            receiver_token_before_alternate_reopen = receiver_wallet.call(
                "get_onyx_asset_balance", token_balance_request
            )
            receiver_wallet.stop()
            receiver_wallet = WalletProcess(
                walletd,
                root,
                receiver_file,
                receiver_data,
                receiver_wallet_rpc,
                onyx_c_rpc,
                WALLET_PASSWORD,
                name="shielded-receiver-rollback-wallet",
            )
            wait_until(
                "receiver wallet reopen through alternate node C",
                lambda: receiver_wallet.status()["top_block_height"] >= rollback_height
                and receiver_wallet.call("get_onyx_status")
                == receiver_before_alternate_reopen
                and receiver_wallet.call(
                    "get_onyx_asset_balance", token_balance_request
                )
                == receiver_token_before_alternate_reopen,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )

            refund_transaction = confirmed_profile_transactions["swap-timeout-refund"]
            # Nodes that reorganized away the original refund restore it to their pools, but the
            # isolated fork never saw that transaction. Submitting only to a node that already has
            # it produces a duplicate response and does not guarantee a fresh broadcast. Submit the
            # identical binary directly to every node that still lacks it, then require universal
            # visibility before reconfirmation.
            for node in (onyx_a, onyx_b, onyx_c, rollback_fork):
                if transaction_known(node, refund_transaction["transaction_hash"]):
                    continue
                response = rpc_response(
                    node.rpc_port,
                    "send_transaction",
                    {"binary_transaction": refund_transaction["binary_transaction"]},
                )
                if "error" in response:
                    raise RuntimeError(
                        f"{node.name} rejected rolled-back refund resubmission: {response!r}"
                    )
            wait_until(
                "rolled-back refund mempool eligibility",
                lambda: all(
                    transaction_known(node, refund_transaction["transaction_hash"])
                    for node in (onyx_a, onyx_b, onyx_c, rollback_fork)
                ),
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            mine_blocks(
                minerd,
                root,
                "rolled-back-refund-reconfirmation",
                rollback_rpc,
                MINING_ADDRESS_A,
                1,
                timeout=1800,
            )
            final_height = 81
            wait_until(
                "rolled-back refund reconfirmation",
                lambda: all(
                    node.status()["top_block_height"] >= final_height
                    for node in (onyx_a, onyx_b, onyx_c, rollback_fork)
                )
                and wallet.status()["top_block_height"] >= final_height
                and receiver_wallet.status()["top_block_height"] >= final_height,
                nodes + [wallet, receiver_wallet],
                timeout=1800,
            )
            restored_states = [
                rpc_call(
                    node.rpc_port,
                    "get_onyx_standard_program_state",
                    {
                        "program_id": swap_refund_parameters["program_id"],
                        "application": swap_refund_parameters["application"],
                    },
                )
                for node in (onyx_a, onyx_b, onyx_c, rollback_fork)
            ]
            if restored_states[1:] != restored_states[:-1] or any(
                not state.get("found")
                or state.get("state") != canonical_field(906)
                or state.get("block_height") != final_height
                for state in restored_states
            ):
                raise RuntimeError(
                    f"refund state did not reconfirm after rollback: {restored_states!r}"
                )
            audits = [
                rpc_call(node.rpc_port, "get_onyx_supply_audit")
                for node in (onyx_a, onyx_b, onyx_c, rollback_fork)
            ]
            if audits[1:] != audits[:-1] or (
                audits[0].get("total_fees") != 500003
                or audits[0].get("circulating_supply") != receiver_native_balance
                or audits[0].get("commitment_count") != profile_commitments
                or audits[0].get("program_count") != profile_program_count
            ):
                raise RuntimeError(
                    f"refund reconfirmation audit did not converge: {audits!r}"
                )
            final_statuses = [onyx_a.status(), onyx_b.status(), onyx_c.status()]
            final_tip = final_statuses[0]["top_block_hash"]
            print(
                "vesting, multisig, and swap profiles passed activation, timelock, threshold, "
                "preimage/refund, pending-conflict, replay, rollback/reopen, state, wallet, and "
                "supply checks"
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
                "pending_standard_program_conflict_precheck": {
                    "maximum_seconds": MAX_PENDING_PROGRAM_CONFLICT_SECONDS,
                    "observed_seconds": pending_conflict_precheck_seconds,
                },
                "scenarios": {
                    "longer_branch_reorganization": "passed",
                    "supply_audit_convergence": "passed",
                    "truncated_v7_rejection": "passed",
                    "wallet_mined_fund_recognition": "passed",
                    "wallet_alternate_node_recovery": "passed",
                    "legacy_to_onyx_migration": "passed",
                    "bridge_tamper_rejection": "passed",
                    "bridge_replay_rejection": "passed",
                    "independent_shielded_transfer": "passed",
                    "pending_shielded_spend_reservation": "passed",
                    "transfer_tamper_rejection": "passed",
                    "nullifier_replay_rejection": "passed",
                    "standard_program_deployment": "passed",
                    "standard_program_deployment_tamper_rejection": "passed",
                    "pending_standard_program_deployment_reservation": "passed",
                    "standard_program_deployment_replay_rejection": "passed",
                    "standard_program_activation": "passed",
                    "stateful_nft_call": "passed",
                    "standard_program_call_tamper_rejection": "passed",
                    "pending_standard_program_state_conflict_rejection": "passed",
                    "standard_program_call_replay_rejection": "passed",
                    "standard_program_state_query_convergence": "passed",
                    "capped_token_program_deployment": "passed",
                    "separate_deployment_funding_and_program_circuits": "passed",
                    "capped_token_deployment_tamper_rejection": "passed",
                    "pending_capped_token_deployment_reservation": "passed",
                    "capped_token_deployment_replay_rejection": "passed",
                    "capped_token_activation": "passed",
                    "token_issuer_authorization_rejection": "passed",
                    "private_token_issuance": "passed",
                    "token_issuance_tamper_rejection": "passed",
                    "pending_token_issuance_sequence_rejection": "passed",
                    "token_issuance_replay_rejection": "passed",
                    "zero_and_over_cap_issuance_rejection": "passed",
                    "private_token_transfer": "passed",
                    "private_token_transfer_tamper_rejection": "passed",
                    "pending_private_token_spend_reservation": "passed",
                    "private_token_transfer_replay_rejection": "passed",
                    "private_token_two_wallet_balance_recovery": "passed",
                    "vesting_program_deployment_and_release": "passed",
                    "vesting_early_release_rejection": "passed",
                    "multisig_program_deployment_and_authorization": "passed",
                    "multisig_threshold_rejection": "passed",
                    "swap_program_deployment": "passed",
                    "swap_preimage_claim": "passed",
                    "swap_wrong_preimage_rejection": "passed",
                    "swap_early_refund_rejection": "passed",
                    "swap_timeout_refund": "passed",
                    "pending_swap_branch_conflict_rejection": "passed",
                    "remaining_standard_profile_state_convergence": "passed",
                    "swap_refund_program_state_rollback": "passed",
                    "swap_refund_commitment_root_rollback": "passed",
                    "swap_refund_mempool_eligibility_restoration": "passed",
                    "swap_refund_reconfirmation_after_node_reopen": "passed",
                    "swap_refund_alternate_node_wallet_reopen": "passed",
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
                    "post_migration_shielded_balance": expected_shielded,
                    "shielded_balance": 0,
                    "remaining_legacy_total": remaining_legacy_total,
                },
                "shielded_transfer": {
                    "amount": transfer_amount,
                    "fee": transfer_fee,
                    "sender_balance": 0,
                    "receiver_balance": transfer_amount,
                    "receiver_onyx_address": receiver_onyx["address"],
                },
                "standard_program_deployment": {
                    "kind": "nft",
                    "program_id": standard_deployment["program_id"],
                    "fee": deployment_fee,
                    "receiver_balance": post_deployment_balance,
                },
                "standard_program_call": {
                    "program_id": standard_deployment["program_id"],
                    "application": nft_application,
                    "activation_height": activation_height,
                    "call_height": call_height,
                    "prior_state": prior_state,
                    "next_state": next_state,
                    "receiver_balance": post_deployment_balance,
                },
                "private_token": {
                    "program_id": token_deployment["program_id"],
                    "metadata": token_metadata,
                    "cap": token_cap,
                    "deployment_fee": token_deployment_fee,
                    "deployment_height": token_deployment_height,
                    "activation_height": token_activation_height,
                    "issuance_height": issuance_height,
                    "issued_amount": issued_amount,
                    "issuance_sequence": issuance["sequence"],
                    "transfer_height": token_transfer_height,
                    "transfer_amount": token_transfer_amount,
                    "transfer_fee": token_transfer_fee,
                    "issuer_token_balance": sender_token_balance,
                    "recipient_token_balance": token_transfer_amount,
                    "issuer_native_balance": private_token_issuer_native_balance,
                    "deployment_funding_circuit_k": 16,
                    "program_execution_circuit_k": 14,
                },
                "remaining_standard_profiles": {
                    "deployment_fee_each": profile_deployment_fee,
                    "final_native_balance": receiver_native_balance,
                    "final_commitment_count": profile_commitments,
                    "final_program_count": profile_program_count,
                    "vesting": {
                        **profile_deployments["vesting"],
                        **vesting_result,
                        "unlock_height": vesting_unlock_height,
                    },
                    "multisig": {
                        **profile_deployments["multisig"],
                        **multisig_result,
                        "threshold": 2,
                        "participant_count": 2,
                    },
                    "swap_claim": {
                        **profile_deployments["swap"],
                        **swap_claim_result,
                        "timeout_height": claim_timeout_height,
                    },
                    "swap_refund": {
                        **swap_refund_result,
                        "timeout_height": refund_timeout_height,
                    },
                    "swap_refund_rollback": {
                        "pre_refund_height": 78,
                        "pre_refund_tip": pre_refund_tip,
                        "first_confirmation_height": 79,
                        "rollback_height": rollback_height,
                        "rollback_tip": rollback_tip,
                        "reconfirmation_height": final_height,
                        "transaction_hash": refund_transaction["transaction_hash"],
                        "restored_commitment_root": rollback_audits[0][
                            "commitment_root"
                        ],
                        "restored_commitment_count": rollback_audits[0][
                            "commitment_count"
                        ],
                    },
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
            if receiver_wallet is not None:
                print(
                    f"\n--- {receiver_wallet.name} log ---\n"
                    f"{receiver_wallet.read_log()}"
                )
            raise
        finally:
            if receiver_wallet is not None:
                receiver_wallet.stop()
            if wallet is not None:
                wallet.stop()
            for node in reversed(nodes):
                node.stop()


if __name__ == "__main__":
    main()
