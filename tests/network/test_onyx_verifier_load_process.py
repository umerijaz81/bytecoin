#!/usr/bin/env python3
"""Real valid-proof load and post-load liveness qualification for an Onyx daemon."""

import argparse
import concurrent.futures
import hashlib
import http.server
import json
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

try:
    from .test_onyx_qualification_process import (
        MINING_ADDRESS_A,
        WALLET_PASSWORD,
        Node,
        WalletProcess,
        connected,
        create_wallet,
        mine_blocks,
        rpc_call,
        rpc_response,
        transaction_known,
        unused_port,
        wait_until,
    )
except ImportError:  # Direct execution places this script's directory on sys.path.
    from test_onyx_qualification_process import (
        MINING_ADDRESS_A,
        WALLET_PASSWORD,
        Node,
        WalletProcess,
        connected,
        create_wallet,
        mine_blocks,
        rpc_call,
        rpc_response,
        transaction_known,
        unused_port,
        wait_until,
    )


SCHEMA = "bytecoin-onyx-verifier-load-process-v1"
ROOT = pathlib.Path(__file__).resolve().parents[2]
LOAD_TOOL = ROOT / "tools" / "onyx_verifier_load.py"
MAX_PENDING_TRANSFER_CONFLICT_SECONDS = 30.0
INVALID_PROOF_ATTEMPTS = 3
INVALID_DEPLOYMENT_PROOF_ATTEMPTS = 2
INVALID_BRIDGE_PROOF_ATTEMPTS = 2


def reciprocal_retry_counters_bounded(metrics):
    """Validate timer requests against global overloads without conflating their domains."""
    retry_requests = (
        metrics["retry_requests_after_retry"] - metrics["retry_requests_before"]
    )
    rejections = (
        metrics["rejected_global_after_retry"]
        - metrics["rejected_global_before"]
    )
    # The primary body always accounts for one rejection. A backup body can already be scheduled
    # before cooldown installation and reject independently of the timer-issued request counter.
    return 1 <= retry_requests <= 2 and 1 <= rejections <= retry_requests + 1


class SubmitBlockCaptureProxy:
    """Forward miner JSON-RPC to a node while retaining submitted block blobs."""

    def __init__(self, listen_port, target_port):
        proxy = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                try:
                    decoded = json.loads(body.decode("utf-8"))
                    if decoded.get("method") == "submit_block":
                        blob = decoded.get("params", {}).get("blocktemplate_blob")
                        if not isinstance(blob, str) or not blob:
                            raise RuntimeError("miner submitted an empty block blob")
                        with proxy.lock:
                            proxy.block_blobs.append(blob)
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise RuntimeError("miner sent malformed JSON-RPC") from error

                request = urllib.request.Request(
                    f"http://127.0.0.1:{target_port}{self.path}",
                    data=body,
                    headers={
                        "Content-Type": self.headers.get(
                            "Content-Type", "application/json-rpc"
                        )
                    },
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(request, timeout=1800) as response:
                        status = response.status
                        response_body = response.read()
                        content_type = response.headers.get(
                            "Content-Type", "application/json"
                        )
                except urllib.error.HTTPError as error:
                    status = error.code
                    response_body = error.read()
                    content_type = error.headers.get(
                        "Content-Type", "application/json"
                    )
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(response_body)))
                self.end_headers()
                self.wfile.write(response_body)

            def log_message(self, _format, *_args):
                return

        self.lock = threading.Lock()
        self.block_blobs = []
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", listen_port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, _type, _value, _traceback):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)


def canonical_utc_now():
    import datetime

    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def write_transaction(path, transaction):
    path.write_text(
        json.dumps(
            {
                "binary_transaction": transaction["binary_transaction"],
                "transaction_hash": transaction["transaction_hash"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def open_transaction_socket(port, binary_transaction, request_id):
    """Submit one complete transaction request and leave response ownership with the caller."""
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "send_transaction",
            "params": {"binary_transaction": binary_transaction},
        },
        separators=(",", ":"),
    ).encode("ascii")
    request = (
        f"POST /json_rpc HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        "Content-Type: application/json-rpc\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: keep-alive\r\n\r\n"
    ).encode("ascii") + body
    connection = socket.create_connection(("127.0.0.1", port), timeout=10)
    connection.sendall(request)
    return connection


def close_socket(connection):
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bytecoind", required=True, type=pathlib.Path)
    parser.add_argument("--minerd", required=True, type=pathlib.Path)
    parser.add_argument("--walletd", required=True, type=pathlib.Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    parser.add_argument("--rpc-timeout", type=float, default=1800.0)
    parser.add_argument("--max-rss-growth-mib", type=float)
    args = parser.parse_args()

    bytecoind = args.bytecoind.resolve()
    minerd = args.minerd.resolve()
    walletd = args.walletd.resolve()
    for label, binary in (
        ("bytecoind", bytecoind),
        ("minerd", minerd),
        ("walletd", walletd),
    ):
        if not binary.is_file():
            parser.error(f"{label} does not exist: {binary}")
    if not LOAD_TOOL.is_file():
        parser.error(f"load runner does not exist: {LOAD_TOOL}")
    if args.rpc_timeout <= 0:
        parser.error("--rpc-timeout must be positive")

    report_path = args.report.resolve()
    load_report_path = report_path.with_name(
        f"{report_path.stem}-raw{report_path.suffix or '.json'}"
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="bytecoin-onyx-load-") as temporary:
        root = pathlib.Path(temporary)
        p2p_port, rpc_port = unused_port(), unused_port()
        relay_p2p_port, relay_rpc_port = unused_port(), unused_port()
        source_wallet_rpc, receiver_wallet_rpc = unused_port(), unused_port()
        nodes = []
        source_wallet = None
        receiver_wallet = None
        try:
            node = Node(bytecoind, root, "onyx-load-node", "onyx", p2p_port, rpc_port)
            nodes.append(node)
            wait_until("Onyx load node RPC", node.status, nodes, timeout=60)
            relay_node = Node(
                bytecoind,
                root,
                "onyx-load-relay-node",
                "onyx",
                relay_p2p_port,
                relay_rpc_port,
                exclusive_port=p2p_port,
            )
            nodes.append(relay_node)
            wait_until(
                "Onyx load peer connection",
                lambda: connected(node.statistics())
                and connected(relay_node.statistics()),
                nodes,
                timeout=60,
            )
            if node.statistics().get("net") != "onyx":
                raise RuntimeError("load node started on the wrong network")

            source_file, source_data = create_wallet(walletd, root, prefix="load-source")
            source_wallet = WalletProcess(
                walletd,
                root,
                source_file,
                source_data,
                source_wallet_rpc,
                rpc_port,
                WALLET_PASSWORD,
                name="load-source-wallet",
            )
            wait_until("source wallet RPC", source_wallet.status, nodes + [source_wallet], timeout=60)
            source_legacy = source_wallet.call("get_addresses")["addresses"]
            source_onyx = source_wallet.call("get_onyx_status")
            if len(source_legacy) != 1 or not source_onyx.get("address"):
                raise RuntimeError("source wallet did not expose both legacy and Onyx identities")

            mine_blocks(minerd, root, "load-source-funding", rpc_port, source_legacy[0], 3)
            wait_until(
                "source wallet funding recognition",
                lambda: source_wallet.status()["top_block_height"] >= 3
                and source_wallet.call(
                    "get_balance", {"address": "", "height_or_depth": -1}
                )["spendable"]
                > 2,
                nodes + [source_wallet],
                timeout=90,
            )
            unspents = source_wallet.call(
                "get_unspents", {"address": source_legacy[0], "height_or_depth": -1}
            )["spendable"]
            migration_output = next((item for item in unspents if item["amount"] > 2), None)
            if migration_output is None:
                raise RuntimeError(f"no legacy output is large enough for load setup: {unspents!r}")

            bridge_fee = 1
            invalid_unsigned = source_wallet.call(
                "create_onyx_bridge",
                {
                    "address": source_onyx["address"],
                    "legacy_amount": migration_output["amount"],
                    "fee": bridge_fee,
                    "legacy_stack_index": migration_output["stack_index"],
                    "legacy_key_image": migration_output["key_image"],
                    "expiry_height": 0,
                    "memo": "authenticated invalid bridge qualification",
                    "qualification_invalid_proof": True,
                },
            )["unsigned_bridge"]
            invalid_signature = source_wallet.call(
                "sign_onyx_bridge",
                {
                    "unsigned_bridge": invalid_unsigned,
                    "qualification_invalid_proof": True,
                },
            )["ownership_signature"]
            invalid_proof_bridge = source_wallet.call(
                "finalize_onyx_bridge",
                {
                    "unsigned_bridge": invalid_unsigned,
                    "ownership_signature": invalid_signature,
                },
            )
            invalid_bridge_before = node.statistics()
            invalid_bridge_started = time.monotonic()
            invalid_bridge_responses = []
            invalid_bridge_attempt_seconds = []
            for _ in range(INVALID_BRIDGE_PROOF_ATTEMPTS):
                attempt_started = time.monotonic()
                invalid_bridge_responses.append(
                    rpc_response(
                        rpc_port,
                        "send_transaction",
                        {
                            "binary_transaction": invalid_proof_bridge[
                                "binary_transaction"
                            ]
                        },
                    )
                )
                invalid_bridge_attempt_seconds.append(
                    round(time.monotonic() - attempt_started, 6)
                )
            invalid_bridge_after = node.statistics()
            authenticated_invalid_bridge = {
                "transaction_hash": invalid_proof_bridge["transaction_hash"],
                "bytes": len(
                    bytes.fromhex(invalid_proof_bridge["binary_transaction"])
                ),
                "attempts": INVALID_BRIDGE_PROOF_ATTEMPTS,
                "attempt_seconds": invalid_bridge_attempt_seconds,
                "elapsed_seconds": round(
                    time.monotonic() - invalid_bridge_started, 6
                ),
                "responses": invalid_bridge_responses,
                "verifier_acquired_before": invalid_bridge_before.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_acquired_after": invalid_bridge_after.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_active_after": invalid_bridge_after.get(
                    "onyx_verifier_active", 0
                ),
                "pool_count_after": invalid_bridge_after.get(
                    "transaction_pool_count", 0
                ),
                "transaction_known_after": transaction_known(
                    node, invalid_proof_bridge["transaction_hash"]
                ),
            }
            if (
                any("error" not in response for response in invalid_bridge_responses)
                or authenticated_invalid_bridge["verifier_acquired_after"]
                != authenticated_invalid_bridge["verifier_acquired_before"]
                + INVALID_BRIDGE_PROOF_ATTEMPTS
                or authenticated_invalid_bridge["verifier_active_after"] != 0
                or authenticated_invalid_bridge["pool_count_after"] != 0
                or authenticated_invalid_bridge["transaction_known_after"]
            ):
                raise RuntimeError(
                    "authenticated invalid bridge did not reach and cleanly leave "
                    f"the verifier: {authenticated_invalid_bridge!r}"
                )

            unsigned = source_wallet.call(
                "create_onyx_bridge",
                {
                    "address": source_onyx["address"],
                    "legacy_amount": migration_output["amount"],
                    "fee": bridge_fee,
                    "legacy_stack_index": migration_output["stack_index"],
                    "legacy_key_image": migration_output["key_image"],
                    "expiry_height": 0,
                    "memo": "verifier load funding",
                },
            )["unsigned_bridge"]
            signature = source_wallet.call(
                "sign_onyx_bridge", {"unsigned_bridge": unsigned}
            )["ownership_signature"]
            bridge = source_wallet.call(
                "finalize_onyx_bridge",
                {"unsigned_bridge": unsigned, "ownership_signature": signature},
            )
            if bridge["transaction_hash"] == invalid_proof_bridge["transaction_hash"]:
                raise RuntimeError("invalid bridge fixture duplicated the valid bridge")
            rpc_call(
                rpc_port,
                "send_transaction",
                {"binary_transaction": bridge["binary_transaction"]},
            )
            mine_blocks(minerd, root, "load-bridge-confirmation", rpc_port, MINING_ADDRESS_A, 1)
            funded_height = 4
            source_balance = migration_output["amount"] - bridge_fee
            wait_until(
                "source shielded funding recognition",
                lambda: source_wallet.status()["top_block_height"] >= funded_height
                and source_wallet.call("get_onyx_status")["balance"] == source_balance
                and relay_node.status()["top_block_height"] >= funded_height,
                nodes + [source_wallet],
                timeout=120,
            )

            receiver_file, receiver_data = create_wallet(
                walletd, root, prefix="load-receiver"
            )
            receiver_wallet = WalletProcess(
                walletd,
                root,
                receiver_file,
                receiver_data,
                receiver_wallet_rpc,
                rpc_port,
                WALLET_PASSWORD,
                name="load-receiver-wallet",
            )
            wait_until(
                "receiver wallet synchronization",
                lambda: receiver_wallet.status()["top_block_height"] >= funded_height,
                nodes + [source_wallet, receiver_wallet],
                timeout=90,
            )
            receiver_onyx = receiver_wallet.call("get_onyx_status")
            if receiver_onyx.get("balance") != 0 or not receiver_onyx.get("address"):
                raise RuntimeError(f"receiver wallet did not start empty: {receiver_onyx!r}")

            transfer_fee = 1
            transfer_amount = source_balance - transfer_fee
            if transfer_amount <= 0:
                raise RuntimeError("shielded funding cannot cover the load transaction fee")
            transactions = []
            for index in range(2):
                transactions.append(
                    source_wallet.call(
                        "create_onyx_transaction",
                        {
                            "address": receiver_onyx["address"],
                            "amount": transfer_amount,
                            "fee": transfer_fee,
                            "expiry_height": 0,
                            "memo": f"parallel valid verifier load {index}",
                        },
                    )
                )
            if transactions[0]["transaction_hash"] == transactions[1]["transaction_hash"]:
                raise RuntimeError("wallet produced duplicate load transactions")
            invalid_proof_transaction = source_wallet.call(
                "create_onyx_transaction",
                {
                    "address": receiver_onyx["address"],
                    "amount": transfer_amount,
                    "fee": transfer_fee,
                    "expiry_height": 0,
                    "memo": "authenticated invalid proof qualification",
                    "qualification_invalid_proof": True,
                },
            )
            if invalid_proof_transaction["transaction_hash"] in {
                transaction["transaction_hash"] for transaction in transactions
            }:
                raise RuntimeError("invalid-proof fixture duplicated a valid transaction")
            invalid_proof_deployment = source_wallet.call(
                "create_onyx_program_deployment",
                {
                    "max_supply": 1000000,
                    "metadata": "authenticated invalid deployment qualification",
                    "activation_height": 0,
                    "deactivation_height": 0,
                    "fee": 100000,
                    "expiry_height": 0,
                    "qualification_invalid_proof": True,
                },
            )
            if invalid_proof_deployment["transaction_hash"] in {
                invalid_proof_transaction["transaction_hash"],
                *(transaction["transaction_hash"] for transaction in transactions),
            }:
                raise RuntimeError("invalid deployment fixture duplicated another transaction")

            transaction_paths = []
            for index, transaction in enumerate(transactions):
                path = root / f"valid-load-{index}.json"
                write_transaction(path, transaction)
                transaction_paths.append(path)

            shutdown_p2p_port, shutdown_rpc_port = unused_port(), unused_port()
            shutdown_auth = "shutdown:qualification"
            shutdown_data = root / "onyx-shutdown-node-data"
            shutdown_node = Node(
                bytecoind,
                root,
                "onyx-shutdown-node",
                "onyx",
                shutdown_p2p_port,
                shutdown_rpc_port,
                exclusive_port=p2p_port,
                data=shutdown_data,
                extra_args=[
                    f"--bytecoind-authorization-private={shutdown_auth}"
                ],
            )
            nodes.append(shutdown_node)
            wait_until(
                "shutdown node synchronization",
                lambda: shutdown_node.status()["top_block_height"] >= funded_height
                and connected(
                    rpc_call(
                        shutdown_rpc_port,
                        "get_statistics",
                        authorization=shutdown_auth,
                    )
                ),
                nodes + [source_wallet, receiver_wallet],
                timeout=120,
            )
            unauthorized_shutdown_rejected = False
            unauthorized_shutdown_response = None
            try:
                unauthorized_shutdown_response = rpc_response(
                    shutdown_rpc_port,
                    "stop_daemon",
                    {"confirm": True},
                )
                # JSON-RPC handler exceptions are returned as a JSON-RPC error with HTTP 200.
                # The HTTP layer itself can also reject authorization before dispatch.
                unauthorized_shutdown_rejected = (
                    "error" in unauthorized_shutdown_response
                )
            except urllib.error.HTTPError as error:
                unauthorized_shutdown_rejected = error.code in (401, 403)
            if not unauthorized_shutdown_rejected or shutdown_node.process.poll() is not None:
                raise RuntimeError("stop_daemon accepted an unauthenticated request")
            refused_shutdown = rpc_response(
                shutdown_rpc_port,
                "stop_daemon",
                {"confirm": False},
                authorization=shutdown_auth,
            )
            if "error" not in refused_shutdown or shutdown_node.process.poll() is not None:
                raise RuntimeError(
                    "stop_daemon did not require explicit confirmation: "
                    f"{refused_shutdown!r}"
                )

            shutdown_stats_before = rpc_call(
                shutdown_rpc_port,
                "get_statistics",
                authorization=shutdown_auth,
            )
            shutdown_body = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "shutdown-valid-proof",
                    "method": "send_transaction",
                    "params": {
                        "binary_transaction": transactions[0]["binary_transaction"]
                    },
                },
                separators=(",", ":"),
            ).encode("ascii")
            shutdown_request = (
                f"POST /json_rpc HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{shutdown_rpc_port}\r\n"
                "Content-Type: application/json-rpc\r\n"
                f"Content-Length: {len(shutdown_body)}\r\n"
                "Connection: keep-alive\r\n\r\n"
            ).encode("ascii") + shutdown_body
            shutdown_socket = socket.create_connection(
                ("127.0.0.1", shutdown_rpc_port), timeout=10
            )
            shutdown_socket.sendall(shutdown_request)
            wait_until(
                "shutdown node active verifier",
                lambda: rpc_call(
                    shutdown_rpc_port,
                    "get_statistics",
                    authorization=shutdown_auth,
                ).get("onyx_verifier_acquired", 0)
                == shutdown_stats_before.get("onyx_verifier_acquired", 0) + 1
                and rpc_call(
                    shutdown_rpc_port,
                    "get_statistics",
                    authorization=shutdown_auth,
                ).get("onyx_verifier_active", 0)
                == 1,
                nodes + [source_wallet, receiver_wallet],
                timeout=30,
            )
            shutdown_started = time.monotonic()
            stop_result = rpc_call(
                shutdown_rpc_port,
                "stop_daemon",
                {"confirm": True},
                authorization=shutdown_auth,
            )
            if stop_result.get("stopping") is not True:
                raise RuntimeError(f"stop_daemon did not acknowledge shutdown: {stop_result!r}")
            try:
                shutdown_node.process.wait(timeout=args.rpc_timeout)
            finally:
                try:
                    shutdown_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                shutdown_socket.close()
            shutdown_elapsed = time.monotonic() - shutdown_started
            shutdown_return_code = shutdown_node.process.returncode
            if shutdown_return_code != 0:
                raise RuntimeError(
                    f"shutdown node exited with {shutdown_return_code}: "
                    f"{shutdown_node.read_log()}"
                )
            shutdown_node.stop()
            nodes.remove(shutdown_node)

            reopened_p2p_port, reopened_rpc_port = unused_port(), unused_port()
            reopened_node = Node(
                bytecoind,
                root,
                "onyx-shutdown-reopened",
                "onyx",
                reopened_p2p_port,
                reopened_rpc_port,
                # Deliberately unreachable: reopening must prove the stopped database itself contains
                # the exact tip rather than silently resynchronizing it from the original node.
                exclusive_port=unused_port(),
                data=shutdown_data,
                extra_args=[
                    f"--bytecoind-authorization-private={shutdown_auth}"
                ],
            )
            nodes.append(reopened_node)
            wait_until(
                "shutdown database reopen",
                lambda: reopened_node.status()["top_block_height"] >= funded_height,
                nodes + [source_wallet, receiver_wallet],
                timeout=120,
            )
            reopened_stats = rpc_call(
                reopened_rpc_port,
                "get_statistics",
                authorization=shutdown_auth,
            )
            graceful_shutdown = {
                "transaction_hash": transactions[0]["transaction_hash"],
                "confirm_false_rejected": "error" in refused_shutdown,
                "unauthenticated_rejected": unauthorized_shutdown_rejected,
                "unauthenticated_response": unauthorized_shutdown_response,
                "stop_acknowledged": stop_result.get("stopping") is True,
                "shutdown_elapsed_seconds": round(shutdown_elapsed, 6),
                "return_code": shutdown_return_code,
                "reopened_height": reopened_node.status()["top_block_height"],
                "reopened_pool_count": reopened_stats.get("transaction_pool_count", 0),
                "reopened_transaction_known": transaction_known(
                    reopened_node, transactions[0]["transaction_hash"]
                ),
            }
            if (
                graceful_shutdown["reopened_height"] != funded_height
                or graceful_shutdown["reopened_pool_count"] != 0
                or graceful_shutdown["reopened_transaction_known"]
            ):
                raise RuntimeError(
                    "graceful verifier shutdown did not reopen at the exact clean state: "
                    f"{graceful_shutdown!r}"
                )
            reopened_stop = rpc_call(
                reopened_rpc_port,
                "stop_daemon",
                {"confirm": True},
                authorization=shutdown_auth,
            )
            if reopened_stop.get("stopping") is not True:
                raise RuntimeError("reopened node did not acknowledge graceful stop")
            reopened_node.process.wait(timeout=30)
            if reopened_node.process.returncode != 0:
                raise RuntimeError("reopened node did not exit cleanly")
            reopened_node.stop()
            nodes.remove(reopened_node)

            stale_data = root / "onyx-stale-verifier-data"
            shutil.copytree(shutdown_data, stale_data)

            capture_port = unused_port()
            with SubmitBlockCaptureProxy(capture_port, rpc_port) as capture:
                mine_blocks(
                    minerd,
                    root,
                    "stale-premined-block",
                    capture_port,
                    MINING_ADDRESS_A,
                    1,
                    timeout=args.rpc_timeout,
                )
            if len(capture.block_blobs) != 1:
                raise RuntimeError(
                    "stale-chain setup did not capture exactly one mined block: "
                    f"{len(capture.block_blobs)}"
                )
            stale_block_blob = capture.block_blobs[0]
            premined_height = funded_height + 1
            wait_until(
                "captured block propagation",
                lambda: node.status()["top_block_height"] >= premined_height
                and relay_node.status()["top_block_height"] >= premined_height
                and source_wallet.status()["top_block_height"] >= premined_height
                and receiver_wallet.status()["top_block_height"] >= premined_height,
                nodes + [source_wallet, receiver_wallet],
                timeout=120,
            )

            stale_p2p_port, stale_rpc_port = unused_port(), unused_port()
            stale_node = Node(
                bytecoind,
                root,
                "onyx-stale-verifier-node",
                "onyx",
                stale_p2p_port,
                stale_rpc_port,
                exclusive_port=unused_port(),
                data=stale_data,
            )
            nodes.append(stale_node)
            stale_base_status = wait_until(
                "stale verifier RPC",
                stale_node.status,
                nodes + [source_wallet, receiver_wallet],
                timeout=60,
            )
            if stale_base_status["top_block_height"] != funded_height:
                raise RuntimeError(
                    "stale verifier copy did not open at the exact base height: "
                    f"expected={funded_height} status={stale_base_status!r}\n"
                    f"{stale_node.read_log()}"
                )
            stale_before = stale_node.statistics()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                stale_submission = executor.submit(
                    rpc_response,
                    stale_rpc_port,
                    "send_transaction",
                    {
                        "binary_transaction": transactions[0]["binary_transaction"]
                    },
                )
                wait_until(
                    "stale verifier active proof",
                    lambda: stale_node.statistics().get("onyx_verifier_acquired", 0)
                    == stale_before.get("onyx_verifier_acquired", 0) + 1
                    and stale_node.statistics().get("onyx_verifier_active", 0) == 1,
                    nodes + [source_wallet, receiver_wallet],
                    timeout=30,
                )
                submitted_block = rpc_call(
                    stale_rpc_port,
                    "submit_block",
                    {"blocktemplate_blob": stale_block_blob},
                )
                if submitted_block.get("orphan_status"):
                    raise RuntimeError("premined stale-chain block was accepted as an orphan")
                wait_until(
                    "stale verifier tip advance",
                    lambda: stale_node.status()["top_block_height"] == funded_height + 1,
                    nodes + [source_wallet, receiver_wallet],
                    timeout=30,
                )
                stale_response = stale_submission.result(timeout=args.rpc_timeout)
            stale_after = stale_node.statistics()
            stale_error = stale_response.get("error", {})
            if (
                stale_error.get("code") != -104
                or "state changed" not in stale_error.get("message", "").lower()
                or stale_after.get("onyx_verifier_acquired", 0)
                != stale_before.get("onyx_verifier_acquired", 0) + 1
                or stale_after.get("onyx_verifier_active", 0) != 0
                or stale_after.get("transaction_pool_count", 0) != 0
                or transaction_known(stale_node, transactions[0]["transaction_hash"])
            ):
                raise RuntimeError(
                    "stale verifier result was not discarded as retryable: "
                    f"response={stale_response!r} stats={stale_after!r}"
                )
            retry_response = rpc_call(
                stale_rpc_port,
                "send_transaction",
                {"binary_transaction": transactions[0]["binary_transaction"]},
            )
            wait_until(
                "stale verifier retry admission",
                lambda: transaction_known(
                    stale_node, transactions[0]["transaction_hash"]
                )
                and stale_node.statistics().get("onyx_verifier_active", 0) == 0,
                nodes + [source_wallet, receiver_wallet],
                timeout=args.rpc_timeout,
            )
            stale_retry_after = stale_node.statistics()
            stale_chain_completion = {
                "transaction_hash": transactions[0]["transaction_hash"],
                "captured_block_bytes": len(bytes.fromhex(stale_block_blob)),
                "base_height": funded_height,
                "advanced_height": stale_node.status()["top_block_height"],
                "stale_response": stale_response,
                "retry_response": retry_response,
                "verifier_acquired_before": stale_before.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_acquired_after_stale": stale_after.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_acquired_after_retry": stale_retry_after.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_active_after_retry": stale_retry_after.get(
                    "onyx_verifier_active", 0
                ),
                "pool_count_after_retry": stale_retry_after.get(
                    "transaction_pool_count", 0
                ),
                "transaction_known_after_retry": transaction_known(
                    stale_node, transactions[0]["transaction_hash"]
                ),
            }
            if (
                stale_chain_completion["verifier_acquired_after_retry"]
                != stale_chain_completion["verifier_acquired_before"] + 2
                or stale_chain_completion["verifier_active_after_retry"] != 0
                or stale_chain_completion["pool_count_after_retry"] != 1
                or not stale_chain_completion["transaction_known_after_retry"]
            ):
                raise RuntimeError(
                    "stale verifier retry did not reuse capacity and admit: "
                    f"{stale_chain_completion!r}"
                )
            stale_node.stop()
            nodes.remove(stale_node)

            # Exercise the single global verifier boundary across real ingress types, not merely
            # two JSON-RPC clients. Start from the clean, offline-persisted height-4 snapshot so this
            # qualification cannot contaminate the primary campaign's pool. The relay admits the
            # first sibling over RPC and announces it to the target over P2P. While the target is
            # verifying that P2P transaction, the other sibling must fail fast over RPC. Once the P2P
            # transaction is admitted, retrying the sibling must hit the authenticated conflict
            # precheck without acquiring the verifier.
            mixed_target_data = root / "onyx-mixed-target-data"
            shutil.copytree(shutdown_data, mixed_target_data)
            mixed_target_p2p, mixed_target_rpc = unused_port(), unused_port()
            mixed_relay_p2p, mixed_relay_rpc = unused_port(), unused_port()
            mixed_target = Node(
                bytecoind,
                root,
                "onyx-mixed-target",
                "onyx",
                mixed_target_p2p,
                mixed_target_rpc,
                exclusive_port=mixed_relay_p2p,
                data=mixed_target_data,
            )
            nodes.append(mixed_target)
            wait_until("mixed-ingress target RPC", mixed_target.status, nodes, timeout=60)
            mixed_relay = Node(
                bytecoind,
                root,
                "onyx-mixed-relay",
                "onyx",
                mixed_relay_p2p,
                mixed_relay_rpc,
                exclusive_port=mixed_target_p2p,
            )
            nodes.append(mixed_relay)
            wait_until(
                "mixed-ingress isolated pair synchronization",
                lambda: connected(mixed_target.statistics())
                and connected(mixed_relay.statistics())
                and mixed_target.status()["top_block_height"] == funded_height
                and mixed_relay.status()["top_block_height"] == funded_height,
                nodes,
                timeout=120,
            )
            mixed_before = mixed_target.statistics()
            if (
                mixed_before.get("transaction_pool_count", 0) != 0
                or transaction_known(mixed_target, transactions[0]["transaction_hash"])
                or transaction_known(mixed_target, transactions[1]["transaction_hash"])
            ):
                raise RuntimeError("mixed-ingress target did not start with an empty pool")

            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                mixed_relay_submission = executor.submit(
                    rpc_call,
                    mixed_relay_rpc,
                    "send_transaction",
                    {"binary_transaction": transactions[0]["binary_transaction"]},
                )
                wait_until(
                    "mixed-ingress P2P verifier activity",
                    lambda: mixed_target.statistics().get("onyx_verifier_acquired", 0)
                    == mixed_before.get("onyx_verifier_acquired", 0) + 1
                    and mixed_target.statistics().get("onyx_verifier_active", 0) == 1,
                    nodes,
                    timeout=args.rpc_timeout,
                )
                mixed_busy_started = time.monotonic()
                mixed_busy_response = rpc_response(
                    mixed_target_rpc,
                    "send_transaction",
                    {"binary_transaction": transactions[1]["binary_transaction"]},
                )
                mixed_busy_elapsed = time.monotonic() - mixed_busy_started
                mixed_during = mixed_target.statistics()
                mixed_relay_response = mixed_relay_submission.result(
                    timeout=args.rpc_timeout
                )

            mixed_busy_error = mixed_busy_response.get("error", {})
            if (
                mixed_busy_error.get("code") != -104
                or "busy" not in mixed_busy_error.get("message", "").lower()
                or mixed_during.get("onyx_verifier_acquired", 0)
                != mixed_before.get("onyx_verifier_acquired", 0) + 1
                or mixed_during.get("onyx_verifier_rejected_global", 0)
                != mixed_before.get("onyx_verifier_rejected_global", 0) + 1
                or transaction_known(mixed_target, transactions[1]["transaction_hash"])
            ):
                raise RuntimeError(
                    "mixed P2P/RPC contention did not fail fast at the global verifier bound: "
                    f"response={mixed_busy_response!r} before={mixed_before!r} "
                    f"during={mixed_during!r}"
                )

            wait_until(
                "mixed-ingress P2P admission",
                lambda: transaction_known(mixed_target, transactions[0]["transaction_hash"])
                and transaction_known(mixed_relay, transactions[0]["transaction_hash"])
                and mixed_target.statistics().get("onyx_verifier_active", 0) == 0,
                nodes,
                timeout=args.rpc_timeout,
            )
            mixed_after_p2p = mixed_target.statistics()
            mixed_retry_started = time.monotonic()
            mixed_retry_response = rpc_call(
                mixed_target_rpc,
                "send_transaction",
                {"binary_transaction": transactions[1]["binary_transaction"]},
            )
            mixed_retry_elapsed = time.monotonic() - mixed_retry_started
            mixed_after_retry = mixed_target.statistics()
            mixed_ingress = {
                "base_height": funded_height,
                "p2p_transaction_hash": transactions[0]["transaction_hash"],
                "rpc_sibling_hash": transactions[1]["transaction_hash"],
                "relay_rpc_response": mixed_relay_response,
                "busy_rpc_response": mixed_busy_response,
                "busy_rpc_elapsed_seconds": round(mixed_busy_elapsed, 6),
                "retry_rpc_response": mixed_retry_response,
                "retry_rpc_elapsed_seconds": round(mixed_retry_elapsed, 6),
                "verifier_acquired_before": mixed_before.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_acquired_during": mixed_during.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_acquired_after_p2p": mixed_after_p2p.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_acquired_after_retry": mixed_after_retry.get(
                    "onyx_verifier_acquired", 0
                ),
                "rejected_global_before": mixed_before.get(
                    "onyx_verifier_rejected_global", 0
                ),
                "rejected_global_during": mixed_during.get(
                    "onyx_verifier_rejected_global", 0
                ),
                "precheck_conflicts_after_p2p": mixed_after_p2p.get(
                    "onyx_verifier_precheck_conflicts", 0
                ),
                "precheck_conflicts_after_retry": mixed_after_retry.get(
                    "onyx_verifier_precheck_conflicts", 0
                ),
                "verifier_active_after_retry": mixed_after_retry.get(
                    "onyx_verifier_active", 0
                ),
                "pool_count_after_retry": mixed_after_retry.get(
                    "transaction_pool_count", 0
                ),
                "p2p_transaction_known_after_retry": transaction_known(
                    mixed_target, transactions[0]["transaction_hash"]
                ),
                "rpc_sibling_known_after_retry": transaction_known(
                    mixed_target, transactions[1]["transaction_hash"]
                ),
            }
            if (
                mixed_ingress["verifier_acquired_after_p2p"]
                != mixed_ingress["verifier_acquired_before"] + 1
                or mixed_ingress["verifier_acquired_after_retry"]
                != mixed_ingress["verifier_acquired_after_p2p"]
                or mixed_ingress["precheck_conflicts_after_retry"]
                != mixed_ingress["precheck_conflicts_after_p2p"] + 1
                or mixed_ingress["verifier_active_after_retry"] != 0
                or mixed_ingress["pool_count_after_retry"] != 1
                or not mixed_ingress["p2p_transaction_known_after_retry"]
                or mixed_ingress["rpc_sibling_known_after_retry"]
                or mixed_retry_elapsed > MAX_PENDING_TRANSFER_CONFLICT_SECONDS
            ):
                raise RuntimeError(
                    "mixed-ingress retry did not use the proof-free conflict path: "
                    f"{mixed_ingress!r}"
                )
            mixed_target.stop()
            nodes.remove(mixed_target)
            mixed_relay.stop()
            nodes.remove(mixed_relay)

            # Reciprocal direction: warm only the relay verifier with an authenticated-invalid proof,
            # then begin a cold abandoned target RPC proof before submitting the valid relay RPC.
            # All three nodes start from the same clean height-4 state. The warm primary relay
            # broadcasts while the cold target verifier is still owned by RPC. The warm backup then
            # reannounces the same body during cooldown. The target must retain that alternate source,
            # survive the primary's disconnect, and retry through the backup after expiry.
            reciprocal_target_data = root / "onyx-reciprocal-target-data"
            shutil.copytree(shutdown_data, reciprocal_target_data)
            reciprocal_target_p2p, reciprocal_target_rpc = unused_port(), unused_port()
            reciprocal_relay_p2p, reciprocal_relay_rpc = unused_port(), unused_port()
            reciprocal_backup_p2p, reciprocal_backup_rpc = unused_port(), unused_port()
            reciprocal_target = Node(
                bytecoind,
                root,
                "onyx-reciprocal-target",
                "onyx",
                reciprocal_target_p2p,
                reciprocal_target_rpc,
                data=reciprocal_target_data,
            )
            nodes.append(reciprocal_target)
            reciprocal_relay = Node(
                bytecoind,
                root,
                "onyx-reciprocal-relay",
                "onyx",
                reciprocal_relay_p2p,
                reciprocal_relay_rpc,
                exclusive_port=reciprocal_target_p2p,
            )
            nodes.append(reciprocal_relay)
            reciprocal_backup = Node(
                bytecoind,
                root,
                "onyx-reciprocal-backup",
                "onyx",
                reciprocal_backup_p2p,
                reciprocal_backup_rpc,
                exclusive_port=reciprocal_target_p2p,
            )
            nodes.append(reciprocal_backup)
            wait_until(
                "reciprocal mixed-ingress three-node synchronization",
                lambda: reciprocal_target.status()["top_block_height"] == funded_height
                and reciprocal_relay.status()["top_block_height"] == funded_height
                and reciprocal_backup.status()["top_block_height"] == funded_height
                and connected(reciprocal_target.statistics())
                and connected(reciprocal_relay.statistics())
                and connected(reciprocal_backup.statistics())
                and len(reciprocal_target.statistics().get("connected_peers", []))
                >= 2,
                nodes,
                timeout=120,
            )
            reciprocal_before = reciprocal_target.statistics()
            reciprocal_relay_before = reciprocal_relay.statistics()
            reciprocal_backup_before = reciprocal_backup.statistics()
            reciprocal_relay_warm_response = rpc_response(
                reciprocal_relay_rpc,
                "send_transaction",
                {
                    "binary_transaction": invalid_proof_transaction[
                        "binary_transaction"
                    ]
                },
            )
            reciprocal_relay_warmed = reciprocal_relay.statistics()
            if (
                "error" not in reciprocal_relay_warm_response
                or reciprocal_relay_warmed.get("onyx_verifier_acquired", 0)
                != reciprocal_relay_before.get("onyx_verifier_acquired", 0) + 1
                or reciprocal_relay_warmed.get("onyx_verifier_active", 0) != 0
                or reciprocal_relay_warmed.get("transaction_pool_count", 0) != 0
            ):
                raise RuntimeError(
                    "reciprocal relay warm-up did not reject through the verifier: "
                    f"response={reciprocal_relay_warm_response!r} "
                    f"before={reciprocal_relay_before!r} warmed={reciprocal_relay_warmed!r}"
                )
            reciprocal_backup_warm_response = rpc_response(
                reciprocal_backup_rpc,
                "send_transaction",
                {
                    "binary_transaction": invalid_proof_transaction[
                        "binary_transaction"
                    ]
                },
            )
            reciprocal_backup_warmed = reciprocal_backup.statistics()
            if (
                "error" not in reciprocal_backup_warm_response
                or reciprocal_backup_warmed.get("onyx_verifier_acquired", 0)
                != reciprocal_backup_before.get("onyx_verifier_acquired", 0) + 1
                or reciprocal_backup_warmed.get("onyx_verifier_active", 0) != 0
                or reciprocal_backup_warmed.get("transaction_pool_count", 0) != 0
            ):
                raise RuntimeError(
                    "reciprocal backup warm-up did not reject through the verifier: "
                    f"response={reciprocal_backup_warm_response!r} "
                    f"before={reciprocal_backup_before!r} "
                    f"warmed={reciprocal_backup_warmed!r}"
                )
            reciprocal_socket = open_transaction_socket(
                reciprocal_target_rpc,
                transactions[1]["binary_transaction"],
                "reciprocal-abandoned-rpc",
            )
            try:
                wait_until(
                    "reciprocal cold target RPC verifier activity",
                    lambda: reciprocal_target.statistics().get(
                        "onyx_verifier_acquired", 0
                    )
                    == reciprocal_before.get("onyx_verifier_acquired", 0) + 1
                    and reciprocal_target.statistics().get("onyx_verifier_active", 0)
                    == 1,
                    nodes,
                    timeout=30,
                )
                # Both peers must begin their local valid-proof verification together. Running these
                # RPCs sequentially lets the first target retry cooldown expire while the backup is
                # still verifying on slower hosts; the primary can then be admitted before the
                # alternate descriptor is announced, which does not exercise source retention at
                # all. The relay gets a deterministic scheduling head start, while the backup starts
                # as soon as the relay owns its local verifier.
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    relay_started = time.monotonic()
                    relay_future = executor.submit(
                        rpc_call,
                        reciprocal_relay_rpc,
                        "send_transaction",
                        {"binary_transaction": transactions[0]["binary_transaction"]},
                    )
                    wait_until(
                        "reciprocal relay local verifier activity",
                        lambda: reciprocal_relay.statistics().get(
                            "onyx_verifier_acquired", 0
                        )
                        == reciprocal_relay_warmed.get("onyx_verifier_acquired", 0) + 1
                        and reciprocal_relay.statistics().get(
                            "onyx_verifier_active", 0
                        )
                        == 1,
                        nodes,
                        timeout=30,
                    )
                    backup_future = executor.submit(
                        rpc_call,
                        reciprocal_backup_rpc,
                        "send_transaction",
                        {"binary_transaction": transactions[0]["binary_transaction"]},
                    )
                    reciprocal_relay_response = relay_future.result()
                    reciprocal_relay_elapsed = time.monotonic() - relay_started
                    wait_until(
                        "reciprocal P2P overload cooldown",
                        lambda: connected(reciprocal_target.statistics())
                        and connected(reciprocal_relay.statistics())
                        and transaction_known(
                            reciprocal_relay, transactions[0]["transaction_hash"]
                        )
                        and reciprocal_target.statistics().get(
                            "onyx_verifier_retry_cooldowns", 0
                        )
                        == 1
                        and reciprocal_target.statistics().get(
                            "transaction_downloads_active", 0
                        )
                        == 0
                        and reciprocal_target.statistics().get(
                            "onyx_verifier_pending_retries", 0
                        )
                        == 1,
                        nodes,
                        timeout=45,
                    )
                    reciprocal_after_overload = reciprocal_target.statistics()
                    reciprocal_backup_response = backup_future.result()
                wait_until(
                    "reciprocal alternate retry source retention",
                    lambda: transaction_known(
                        reciprocal_backup, transactions[0]["transaction_hash"]
                    )
                    and reciprocal_target.statistics().get(
                        "onyx_verifier_pending_retries", 0
                    )
                    == 1
                    and reciprocal_target.statistics().get(
                        "onyx_verifier_retry_sources", 0
                    )
                    == 2,
                    nodes,
                    timeout=45,
                )
                reciprocal_after_alternate = reciprocal_target.statistics()

                reciprocal_relay.stop()
                nodes.remove(reciprocal_relay)
                wait_until(
                    "reciprocal primary source disconnect failover",
                    lambda: connected(reciprocal_target.statistics())
                    and connected(reciprocal_backup.statistics())
                    and len(
                        reciprocal_target.statistics().get("connected_peers", [])
                    )
                    >= 1
                    and reciprocal_target.statistics().get(
                        "onyx_verifier_pending_retries", 0
                    )
                    == 1
                    and reciprocal_target.statistics().get(
                        "onyx_verifier_retry_sources", 0
                    )
                    == 1,
                    nodes,
                    timeout=30,
                )
                reciprocal_after_failover = reciprocal_target.statistics()
            finally:
                close_socket(reciprocal_socket)
            if (
                reciprocal_after_overload.get("onyx_verifier_acquired", 0)
                != reciprocal_before.get("onyx_verifier_acquired", 0) + 1
                or reciprocal_after_overload.get("onyx_verifier_rejected_global", 0)
                != reciprocal_before.get("onyx_verifier_rejected_global", 0) + 1
                or not connected(reciprocal_after_overload)
                or transaction_known(
                    reciprocal_target, transactions[0]["transaction_hash"]
                )
            ):
                raise RuntimeError(
                    "reciprocal P2P overload was not bounded and non-banning: "
                    f"before={reciprocal_before!r} after={reciprocal_after_overload!r}"
                )

            wait_until(
                "reciprocal abandoned RPC cleanup",
                lambda: reciprocal_target.statistics().get(
                    "onyx_verifier_abandoned_rpcs", 0
                )
                == reciprocal_before.get("onyx_verifier_abandoned_rpcs", 0) + 1
                and reciprocal_target.statistics().get("onyx_verifier_active", 0) == 0
                and reciprocal_target.statistics().get("transaction_pool_count", 0) == 0,
                nodes,
                timeout=args.rpc_timeout,
            )
            reciprocal_after_cleanup = reciprocal_target.statistics()
            if (
                transaction_known(
                    reciprocal_target, transactions[0]["transaction_hash"]
                )
                or transaction_known(
                    reciprocal_target, transactions[1]["transaction_hash"]
                )
            ):
                raise RuntimeError("reciprocal target admitted work before cooldown retry")

            automatic_retry_started = time.monotonic()
            wait_until(
                "automatic reciprocal P2P retry admission",
                lambda: transaction_known(
                    reciprocal_target, transactions[0]["transaction_hash"]
                )
                and reciprocal_target.statistics().get("onyx_verifier_active", 0) == 0
                and reciprocal_target.statistics().get("onyx_verifier_acquired", 0)
                == reciprocal_before.get("onyx_verifier_acquired", 0) + 2
                and reciprocal_target.statistics().get(
                    "onyx_verifier_retry_cooldowns", 0
                )
                == 0
                and reciprocal_target.statistics().get(
                    "onyx_verifier_pending_retries", 0
                )
                == 0
                and reciprocal_target.statistics().get(
                    "transaction_downloads_active", 0
                )
                == 0,
                nodes,
                timeout=max(args.rpc_timeout, 90),
            )
            automatic_retry_elapsed = time.monotonic() - automatic_retry_started
            reciprocal_after_retry = reciprocal_target.statistics()
            reciprocal_mixed_ingress = {
                "base_height": funded_height,
                "abandoned_rpc_transaction_hash": transactions[1][
                    "transaction_hash"
                ],
                "p2p_transaction_hash": transactions[0]["transaction_hash"],
                "relay_warm_response": reciprocal_relay_warm_response,
                "relay_rpc_response": reciprocal_relay_response,
                "backup_warm_response": reciprocal_backup_warm_response,
                "backup_rpc_response": reciprocal_backup_response,
                "relay_rpc_seconds_after_cold_target_started": round(
                    reciprocal_relay_elapsed, 6
                ),
                "automatic_retry_seconds_after_rpc_cleanup": round(
                    automatic_retry_elapsed, 6
                ),
                "verifier_acquired_before": reciprocal_before.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_acquired_after_overload": reciprocal_after_overload.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_acquired_after_retry": reciprocal_after_retry.get(
                    "onyx_verifier_acquired", 0
                ),
                "rejected_global_before": reciprocal_before.get(
                    "onyx_verifier_rejected_global", 0
                ),
                "rejected_global_after_overload": reciprocal_after_overload.get(
                    "onyx_verifier_rejected_global", 0
                ),
                "rejected_global_after_retry": reciprocal_after_retry.get(
                    "onyx_verifier_rejected_global", 0
                ),
                "cooldowns_after_overload": reciprocal_after_overload.get(
                    "onyx_verifier_retry_cooldowns", 0
                ),
                "cooldowns_after_retry": reciprocal_after_retry.get(
                    "onyx_verifier_retry_cooldowns", 0
                ),
                "downloads_after_overload": reciprocal_after_overload.get(
                    "transaction_downloads_active", 0
                ),
                "downloads_after_retry": reciprocal_after_retry.get(
                    "transaction_downloads_active", 0
                ),
                "pending_retries_after_overload": reciprocal_after_overload.get(
                    "onyx_verifier_pending_retries", 0
                ),
                "pending_retries_after_retry": reciprocal_after_retry.get(
                    "onyx_verifier_pending_retries", 0
                ),
                "retry_sources_after_overload": reciprocal_after_overload.get(
                    "onyx_verifier_retry_sources", 0
                ),
                "retry_sources_after_alternate": reciprocal_after_alternate.get(
                    "onyx_verifier_retry_sources", 0
                ),
                "retry_sources_after_primary_disconnect": reciprocal_after_failover.get(
                    "onyx_verifier_retry_sources", 0
                ),
                "retry_sources_after_retry": reciprocal_after_retry.get(
                    "onyx_verifier_retry_sources", 0
                ),
                "retry_requests_before": reciprocal_before.get(
                    "onyx_verifier_retry_requests", 0
                ),
                "retry_requests_after_retry": reciprocal_after_retry.get(
                    "onyx_verifier_retry_requests", 0
                ),
                "abandoned_rpcs_before": reciprocal_before.get(
                    "onyx_verifier_abandoned_rpcs", 0
                ),
                "abandoned_rpcs_after_cleanup": reciprocal_after_cleanup.get(
                    "onyx_verifier_abandoned_rpcs", 0
                ),
                "pool_count_after_retry": reciprocal_after_retry.get(
                    "transaction_pool_count", 0
                ),
                "peers_connected_after_overload": len(
                    reciprocal_after_overload.get("connected_peers", [])
                ),
                "peers_connected_after_retry": len(
                    reciprocal_after_retry.get("connected_peers", [])
                ),
                "p2p_transaction_known_after_retry": transaction_known(
                    reciprocal_target, transactions[0]["transaction_hash"]
                ),
                "abandoned_rpc_known_after_retry": transaction_known(
                    reciprocal_target, transactions[1]["transaction_hash"]
                ),
            }
            if (
                reciprocal_mixed_ingress["verifier_acquired_after_overload"]
                != reciprocal_mixed_ingress["verifier_acquired_before"] + 1
                or reciprocal_mixed_ingress["verifier_acquired_after_retry"]
                != reciprocal_mixed_ingress["verifier_acquired_before"] + 2
                or reciprocal_mixed_ingress["rejected_global_after_overload"]
                != reciprocal_mixed_ingress["rejected_global_before"] + 1
                or reciprocal_mixed_ingress["cooldowns_after_overload"] != 1
                or reciprocal_mixed_ingress["cooldowns_after_retry"] != 0
                or reciprocal_mixed_ingress["downloads_after_overload"] != 0
                or reciprocal_mixed_ingress["downloads_after_retry"] != 0
                or reciprocal_mixed_ingress["pending_retries_after_overload"] != 1
                or reciprocal_mixed_ingress["pending_retries_after_retry"] != 0
                or reciprocal_mixed_ingress["retry_sources_after_overload"] != 1
                or reciprocal_mixed_ingress["retry_sources_after_alternate"] != 2
                or reciprocal_mixed_ingress[
                    "retry_sources_after_primary_disconnect"
                ]
                != 1
                or reciprocal_mixed_ingress["retry_sources_after_retry"] != 0
                or not reciprocal_retry_counters_bounded(reciprocal_mixed_ingress)
                or reciprocal_mixed_ingress["abandoned_rpcs_after_cleanup"]
                != reciprocal_mixed_ingress["abandoned_rpcs_before"] + 1
                or reciprocal_mixed_ingress["pool_count_after_retry"] != 1
                or reciprocal_mixed_ingress["peers_connected_after_overload"] == 0
                or reciprocal_mixed_ingress["peers_connected_after_retry"] == 0
                or not reciprocal_mixed_ingress[
                    "p2p_transaction_known_after_retry"
                ]
                or reciprocal_mixed_ingress["abandoned_rpc_known_after_retry"]
            ):
                raise RuntimeError(
                    "reciprocal P2P cooldown did not automatically retry and admit: "
                    f"{reciprocal_mixed_ingress!r}"
                )
            reciprocal_target.stop()
            nodes.remove(reciprocal_target)
            reciprocal_backup.stop()
            nodes.remove(reciprocal_backup)

            abandoned_before = node.statistics()
            abandoned_socket = open_transaction_socket(
                rpc_port,
                transactions[0]["binary_transaction"],
                "abandoned-valid-proof",
            )
            try:
                wait_until(
                    "abandoned RPC verifier start",
                    lambda: node.statistics().get("onyx_verifier_acquired", 0)
                    == abandoned_before.get("onyx_verifier_acquired", 0) + 1
                    and node.statistics().get("onyx_verifier_active", 0) == 1,
                    nodes + [source_wallet, receiver_wallet],
                    timeout=30,
                )
            finally:
                close_socket(abandoned_socket)

            wait_until(
                "abandoned RPC verifier cleanup",
                lambda: node.statistics().get("onyx_verifier_abandoned_rpcs", 0)
                == abandoned_before.get("onyx_verifier_abandoned_rpcs", 0) + 1
                and node.statistics().get("onyx_verifier_active", 0) == 0,
                nodes + [source_wallet, receiver_wallet],
                timeout=args.rpc_timeout,
            )
            abandoned_after = node.statistics()
            abandoned_rpc_cleanup = {
                "transaction_hash": transactions[0]["transaction_hash"],
                "verifier_acquired_before": abandoned_before.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_acquired_after": abandoned_after.get(
                    "onyx_verifier_acquired", 0
                ),
                "abandoned_rpcs_before": abandoned_before.get(
                    "onyx_verifier_abandoned_rpcs", 0
                ),
                "abandoned_rpcs_after": abandoned_after.get(
                    "onyx_verifier_abandoned_rpcs", 0
                ),
                "verifier_active_after": abandoned_after.get(
                    "onyx_verifier_active", 0
                ),
                "pool_count_after": abandoned_after.get("transaction_pool_count", 0),
                "transaction_known_after": transaction_known(
                    node, transactions[0]["transaction_hash"]
                ),
            }
            if (
                abandoned_rpc_cleanup["verifier_acquired_after"]
                != abandoned_rpc_cleanup["verifier_acquired_before"] + 1
                or abandoned_rpc_cleanup["abandoned_rpcs_after"]
                != abandoned_rpc_cleanup["abandoned_rpcs_before"] + 1
                or abandoned_rpc_cleanup["verifier_active_after"] != 0
                or abandoned_rpc_cleanup["pool_count_after"] != 0
                or abandoned_rpc_cleanup["transaction_known_after"]
            ):
                raise RuntimeError(
                    "abandoned valid-proof RPC did not cleanly release without admission: "
                    f"{abandoned_rpc_cleanup!r}"
                )

            invalid_before = node.statistics()
            invalid_started = time.monotonic()
            invalid_responses = []
            invalid_attempt_seconds = []
            for _ in range(INVALID_PROOF_ATTEMPTS):
                attempt_started = time.monotonic()
                invalid_responses.append(
                    rpc_response(
                        rpc_port,
                        "send_transaction",
                        {
                            "binary_transaction": invalid_proof_transaction[
                                "binary_transaction"
                            ]
                        },
                    )
                )
                invalid_attempt_seconds.append(
                    round(time.monotonic() - attempt_started, 6)
                )
            invalid_elapsed = time.monotonic() - invalid_started
            invalid_after = node.statistics()
            authenticated_invalid_proof = {
                "transaction_hash": invalid_proof_transaction["transaction_hash"],
                "bytes": len(
                    bytes.fromhex(invalid_proof_transaction["binary_transaction"])
                ),
                "attempts": INVALID_PROOF_ATTEMPTS,
                "attempt_seconds": invalid_attempt_seconds,
                "elapsed_seconds": round(invalid_elapsed, 6),
                "responses": invalid_responses,
                "verifier_acquired_before": invalid_before.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_acquired_after": invalid_after.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_active_after": invalid_after.get(
                    "onyx_verifier_active", 0
                ),
                "pool_count_after": invalid_after.get("transaction_pool_count", 0),
                "transaction_known_after": transaction_known(
                    node, invalid_proof_transaction["transaction_hash"]
                ),
            }
            if (
                any("error" not in response for response in invalid_responses)
                or authenticated_invalid_proof["verifier_acquired_after"]
                != authenticated_invalid_proof["verifier_acquired_before"]
                + INVALID_PROOF_ATTEMPTS
                or authenticated_invalid_proof["verifier_active_after"] != 0
                or authenticated_invalid_proof["pool_count_after"] != 0
                or authenticated_invalid_proof["transaction_known_after"]
            ):
                raise RuntimeError(
                    "authenticated invalid proof did not reach and cleanly leave the verifier: "
                    f"{authenticated_invalid_proof!r}"
                )

            invalid_deployment_before = node.statistics()
            invalid_deployment_started = time.monotonic()
            invalid_deployment_responses = []
            invalid_deployment_attempt_seconds = []
            for _ in range(INVALID_DEPLOYMENT_PROOF_ATTEMPTS):
                attempt_started = time.monotonic()
                invalid_deployment_responses.append(
                    rpc_response(
                        rpc_port,
                        "send_transaction",
                        {
                            "binary_transaction": invalid_proof_deployment[
                                "binary_transaction"
                            ]
                        },
                    )
                )
                invalid_deployment_attempt_seconds.append(
                    round(time.monotonic() - attempt_started, 6)
                )
            invalid_deployment_after = node.statistics()
            authenticated_invalid_deployment = {
                "transaction_hash": invalid_proof_deployment["transaction_hash"],
                "program_id": invalid_proof_deployment["program_id"],
                "bytes": len(
                    bytes.fromhex(invalid_proof_deployment["binary_transaction"])
                ),
                "attempts": INVALID_DEPLOYMENT_PROOF_ATTEMPTS,
                "attempt_seconds": invalid_deployment_attempt_seconds,
                "elapsed_seconds": round(
                    time.monotonic() - invalid_deployment_started, 6
                ),
                "responses": invalid_deployment_responses,
                "verifier_acquired_before": invalid_deployment_before.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_acquired_after": invalid_deployment_after.get(
                    "onyx_verifier_acquired", 0
                ),
                "verifier_active_after": invalid_deployment_after.get(
                    "onyx_verifier_active", 0
                ),
                "pool_count_after": invalid_deployment_after.get(
                    "transaction_pool_count", 0
                ),
                "transaction_known_after": transaction_known(
                    node, invalid_proof_deployment["transaction_hash"]
                ),
            }
            if (
                any("error" not in response for response in invalid_deployment_responses)
                or authenticated_invalid_deployment["verifier_acquired_after"]
                != authenticated_invalid_deployment["verifier_acquired_before"]
                + INVALID_DEPLOYMENT_PROOF_ATTEMPTS
                or authenticated_invalid_deployment["verifier_active_after"] != 0
                or authenticated_invalid_deployment["pool_count_after"] != 0
                or authenticated_invalid_deployment["transaction_known_after"]
            ):
                raise RuntimeError(
                    "authenticated invalid deployment did not reach and cleanly leave "
                    f"the verifier: {authenticated_invalid_deployment!r}"
                )

            baseline_status = node.status()
            baseline_audit = rpc_call(rpc_port, "get_onyx_supply_audit")
            command = [
                sys.executable,
                str(LOAD_TOOL),
                "--rpc-url",
                f"http://127.0.0.1:{rpc_port}/json_rpc",
                "--authorization",
                "local-load:qualification",
                "--pid",
                str(node.process.pid),
                "--transaction-file",
                str(transaction_paths[0]),
                "--transaction-file",
                str(transaction_paths[1]),
                "--parallel",
                "2",
                "--sample-interval",
                "0.05",
                "--rpc-timeout",
                str(args.rpc_timeout),
                "--revision",
                args.revision,
                "--report",
                str(load_report_path),
            ]
            if args.max_rss_growth_mib is not None:
                command.extend(
                    ["--max-rss-growth-mib", str(args.max_rss_growth_mib)]
                )
            load_run = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=args.rpc_timeout + 120,
            )
            if not load_report_path.is_file():
                raise RuntimeError(
                    "load runner did not write its report\n"
                    f"stdout:\n{load_run.stdout}\nstderr:\n{load_run.stderr}"
                )
            load_report = json.loads(load_report_path.read_text(encoding="utf-8"))
            if load_run.returncode != 0 or not load_report.get("passed"):
                raise RuntimeError(
                    "valid-proof load runner failed\n"
                    f"stdout:\n{load_run.stdout}\nstderr:\n{load_run.stderr}\n"
                    f"report:\n{json.dumps(load_report, indent=2, sort_keys=True)}"
                )
            classifications = sorted(
                item.get("classification") for item in load_report["submissions"]
            )
            if classifications != ["accepted", "verifier_busy"]:
                raise RuntimeError(
                    f"load did not produce one accepted and one bounded-overload response: "
                    f"{classifications!r}"
                )
            verifier_acquired_after_load = node.statistics().get(
                "onyx_verifier_acquired", 0
            )
            authenticated_invalid_proof["verifier_acquired_after_valid_load"] = (
                verifier_acquired_after_load
            )
            accepted_submission = next(
                item
                for item in load_report["submissions"]
                if item.get("classification") == "accepted"
            )
            tx_hash_by_sha256 = {
                hashlib.sha256(
                    bytes.fromhex(transaction["binary_transaction"])
                ).hexdigest(): transaction["transaction_hash"]
                for transaction in transactions
            }
            accepted_transaction_hash = tx_hash_by_sha256[
                accepted_submission["sha256"]
            ]
            wait_until(
                "accepted Onyx transaction P2P propagation",
                lambda: transaction_known(relay_node, accepted_transaction_hash)
                and relay_node.statistics().get("onyx_verifier_active", 0) == 0,
                nodes + [source_wallet, receiver_wallet],
                timeout=args.rpc_timeout,
            )

            conflicting_transaction = next(
                transaction
                for transaction in transactions
                if transaction["transaction_hash"] != accepted_transaction_hash
            )
            verifier_before_conflict = node.statistics().get(
                "onyx_verifier_acquired", 0
            )
            prechecks_before_conflict = node.statistics().get(
                "onyx_verifier_precheck_conflicts", 0
            )
            conflict_started = time.monotonic()
            conflict_response = rpc_call(
                rpc_port,
                "send_transaction",
                {"binary_transaction": conflicting_transaction["binary_transaction"]},
            )
            conflict_elapsed = time.monotonic() - conflict_started
            verifier_after_conflict = node.statistics().get(
                "onyx_verifier_acquired", 0
            )
            prechecks_after_conflict = node.statistics().get(
                "onyx_verifier_precheck_conflicts", 0
            )
            transfer_conflict_precheck = {
                "transaction_hash": conflicting_transaction["transaction_hash"],
                "elapsed_seconds": round(conflict_elapsed, 6),
                "verifier_acquired_before": verifier_before_conflict,
                "verifier_acquired_after": verifier_after_conflict,
                "precheck_conflicts_before": prechecks_before_conflict,
                "precheck_conflicts_after": prechecks_after_conflict,
                "response": conflict_response,
            }
            if conflict_elapsed > MAX_PENDING_TRANSFER_CONFLICT_SECONDS:
                raise RuntimeError(
                    "pending transfer conflict exceeded the proof-free precheck ceiling: "
                    f"elapsed={conflict_elapsed:.3f}s"
                )
            if verifier_after_conflict != verifier_before_conflict:
                raise RuntimeError(
                    "pending transfer conflict acquired the expensive verifier: "
                    f"before={verifier_before_conflict} after={verifier_after_conflict}"
                )
            if prechecks_after_conflict != prechecks_before_conflict + 1:
                raise RuntimeError(
                    "pending transfer conflict did not increment the proof-free precheck counter: "
                    f"before={prechecks_before_conflict} after={prechecks_after_conflict}"
                )
            if (
                transaction_known(node, conflicting_transaction["transaction_hash"])
                or node.statistics().get("transaction_pool_count") != 1
            ):
                raise RuntimeError("node admitted the conflicting sibling transfer")

            accepted_transaction = next(
                transaction
                for transaction in transactions
                if transaction["transaction_hash"] == accepted_transaction_hash
            )
            verifier_before_duplicate = node.statistics().get(
                "onyx_verifier_acquired", 0
            )
            prechecks_before_duplicate = node.statistics().get(
                "onyx_verifier_precheck_conflicts", 0
            )
            duplicate_started = time.monotonic()
            duplicate_response = rpc_call(
                rpc_port,
                "send_transaction",
                {"binary_transaction": accepted_transaction["binary_transaction"]},
            )
            duplicate_elapsed = time.monotonic() - duplicate_started
            verifier_after_duplicate = node.statistics().get(
                "onyx_verifier_acquired", 0
            )
            prechecks_after_duplicate = node.statistics().get(
                "onyx_verifier_precheck_conflicts", 0
            )
            pool_count_after_duplicate = node.statistics().get(
                "transaction_pool_count", 0
            )
            exact_duplicate_precheck = {
                "transaction_hash": accepted_transaction_hash,
                "elapsed_seconds": round(duplicate_elapsed, 6),
                "verifier_acquired_before": verifier_before_duplicate,
                "verifier_acquired_after": verifier_after_duplicate,
                "precheck_conflicts_before": prechecks_before_duplicate,
                "precheck_conflicts_after": prechecks_after_duplicate,
                "pool_count_after": pool_count_after_duplicate,
                "response": duplicate_response,
            }
            if duplicate_elapsed > MAX_PENDING_TRANSFER_CONFLICT_SECONDS:
                raise RuntimeError(
                    "exact duplicate exceeded the proof-free admission ceiling: "
                    f"elapsed={duplicate_elapsed:.3f}s"
                )
            if verifier_after_duplicate != verifier_before_duplicate:
                raise RuntimeError(
                    "exact duplicate acquired the expensive verifier: "
                    f"before={verifier_before_duplicate} after={verifier_after_duplicate}"
                )
            if prechecks_after_duplicate != prechecks_before_duplicate:
                raise RuntimeError(
                    "exact duplicate was misclassified as an authenticated conflict: "
                    f"before={prechecks_before_duplicate} after={prechecks_after_duplicate}"
                )
            if pool_count_after_duplicate != 1:
                raise RuntimeError("exact duplicate changed the transaction pool count")

            relay_after_load_status = relay_node.status()
            after_load_status = node.status()
            if (
                after_load_status["top_block_height"]
                != baseline_status["top_block_height"]
                or after_load_status["top_block_hash"]
                != baseline_status["top_block_hash"]
            ):
                raise RuntimeError("unmined verifier load changed the chain tip")

            mine_blocks(
                minerd,
                root,
                "load-post-admission-progress",
                rpc_port,
                MINING_ADDRESS_A,
                1,
                timeout=args.rpc_timeout,
            )
            final_height = baseline_status["top_block_height"] + 1
            wait_until(
                "post-load chain and wallet progress",
                lambda: node.status()["top_block_height"] >= final_height
                and relay_node.status()["top_block_height"] >= final_height
                and source_wallet.status()["top_block_height"] >= final_height
                and receiver_wallet.status()["top_block_height"] >= final_height
                and source_wallet.call("get_onyx_status")["balance"] == 0
                and receiver_wallet.call("get_onyx_status")["balance"]
                == transfer_amount,
                nodes + [source_wallet, receiver_wallet],
                timeout=180,
            )
            final_status = node.status()
            final_audit = rpc_call(rpc_port, "get_onyx_supply_audit")
            relay_final_audit = rpc_call(relay_rpc_port, "get_onyx_supply_audit")
            supply_ok = (
                final_audit.get("total_bridged") == migration_output["amount"]
                and final_audit.get("total_fees") == bridge_fee + transfer_fee
                and final_audit.get("circulating_supply") == transfer_amount
                and final_audit.get("commitment_count") == 2
                and relay_final_audit == final_audit
            )
            checks = {
                "raw_load_report_passed": bool(load_report.get("passed")),
                "graceful_shutdown_during_verification": (
                    graceful_shutdown["confirm_false_rejected"]
                    and graceful_shutdown["unauthenticated_rejected"]
                    and graceful_shutdown["stop_acknowledged"]
                    and graceful_shutdown["return_code"] == 0
                    and graceful_shutdown["reopened_height"] == funded_height
                    and graceful_shutdown["reopened_pool_count"] == 0
                    and not graceful_shutdown["reopened_transaction_known"]
                ),
                "stale_chain_completion_discarded_and_retried": (
                    stale_chain_completion["advanced_height"] == funded_height + 1
                    and stale_chain_completion["stale_response"]
                    .get("error", {})
                    .get("code")
                    == -104
                    and stale_chain_completion["verifier_acquired_after_stale"]
                    == stale_chain_completion["verifier_acquired_before"] + 1
                    and stale_chain_completion["verifier_acquired_after_retry"]
                    == stale_chain_completion["verifier_acquired_before"] + 2
                    and stale_chain_completion["pool_count_after_retry"] == 1
                    and stale_chain_completion["transaction_known_after_retry"]
                ),
                "mixed_p2p_rpc_global_bound": (
                    mixed_ingress["busy_rpc_response"]
                    .get("error", {})
                    .get("code")
                    == -104
                    and mixed_ingress["verifier_acquired_during"]
                    == mixed_ingress["verifier_acquired_before"] + 1
                    and mixed_ingress["rejected_global_during"]
                    == mixed_ingress["rejected_global_before"] + 1
                    and mixed_ingress["verifier_acquired_after_p2p"]
                    == mixed_ingress["verifier_acquired_before"] + 1
                ),
                "mixed_ingress_retry_conflict_skipped_verifier": (
                    mixed_ingress["verifier_acquired_after_retry"]
                    == mixed_ingress["verifier_acquired_after_p2p"]
                    and mixed_ingress["precheck_conflicts_after_retry"]
                    == mixed_ingress["precheck_conflicts_after_p2p"] + 1
                    and mixed_ingress["pool_count_after_retry"] == 1
                    and mixed_ingress["p2p_transaction_known_after_retry"]
                    and not mixed_ingress["rpc_sibling_known_after_retry"]
                ),
                "reciprocal_p2p_overload_non_banning_and_bounded": (
                    reciprocal_mixed_ingress["verifier_acquired_after_overload"]
                    == reciprocal_mixed_ingress["verifier_acquired_before"] + 1
                    and reciprocal_mixed_ingress["rejected_global_after_overload"]
                    == reciprocal_mixed_ingress["rejected_global_before"] + 1
                    and reciprocal_mixed_ingress["cooldowns_after_overload"] == 1
                    and reciprocal_mixed_ingress["downloads_after_overload"] == 0
                    and reciprocal_mixed_ingress["pending_retries_after_overload"]
                    == 1
                    and reciprocal_mixed_ingress["peers_connected_after_overload"]
                    > 0
                ),
                "reciprocal_p2p_automatic_retry_after_cooldown": (
                    reciprocal_mixed_ingress["verifier_acquired_after_retry"]
                    == reciprocal_mixed_ingress["verifier_acquired_before"] + 2
                    and reciprocal_mixed_ingress["cooldowns_after_retry"] == 0
                    and reciprocal_mixed_ingress["downloads_after_retry"] == 0
                    and reciprocal_mixed_ingress["pending_retries_after_retry"] == 0
                    and reciprocal_mixed_ingress["pool_count_after_retry"] == 1
                    and reciprocal_mixed_ingress["peers_connected_after_retry"] > 0
                    and reciprocal_mixed_ingress[
                        "p2p_transaction_known_after_retry"
                    ]
                    and not reciprocal_mixed_ingress[
                        "abandoned_rpc_known_after_retry"
                    ]
                ),
                "reciprocal_p2p_alternate_source_failover_bounded": (
                    reciprocal_mixed_ingress["retry_sources_after_overload"] == 1
                    and reciprocal_mixed_ingress["retry_sources_after_alternate"]
                    == 2
                    and reciprocal_mixed_ingress[
                        "retry_sources_after_primary_disconnect"
                    ]
                    == 1
                    and reciprocal_mixed_ingress["retry_sources_after_retry"] == 0
                    and reciprocal_retry_counters_bounded(reciprocal_mixed_ingress)
                ),
                "abandoned_rpc_released_without_admission": (
                    abandoned_rpc_cleanup["verifier_acquired_after"]
                    == abandoned_rpc_cleanup["verifier_acquired_before"] + 1
                    and abandoned_rpc_cleanup["abandoned_rpcs_after"]
                    == abandoned_rpc_cleanup["abandoned_rpcs_before"] + 1
                    and abandoned_rpc_cleanup["verifier_active_after"] == 0
                    and abandoned_rpc_cleanup["pool_count_after"] == 0
                    and not abandoned_rpc_cleanup["transaction_known_after"]
                ),
                "authenticated_invalid_proof_reached_verifier_without_admission": (
                    all(
                        "error" in response
                        for response in authenticated_invalid_proof["responses"]
                    )
                    and authenticated_invalid_proof["verifier_acquired_after"]
                    == authenticated_invalid_proof["verifier_acquired_before"]
                    + authenticated_invalid_proof["attempts"]
                    and authenticated_invalid_proof["verifier_active_after"] == 0
                    and authenticated_invalid_proof["pool_count_after"] == 0
                    and not authenticated_invalid_proof["transaction_known_after"]
                    and authenticated_invalid_proof[
                        "verifier_acquired_after_valid_load"
                    ]
                    >= authenticated_invalid_proof["verifier_acquired_after"] + 1
                ),
                "authenticated_invalid_deployment_reached_verifier_without_admission": (
                    all(
                        "error" in response
                        for response in authenticated_invalid_deployment["responses"]
                    )
                    and authenticated_invalid_deployment["verifier_acquired_after"]
                    == authenticated_invalid_deployment["verifier_acquired_before"]
                    + authenticated_invalid_deployment["attempts"]
                    and authenticated_invalid_deployment["verifier_active_after"] == 0
                    and authenticated_invalid_deployment["pool_count_after"] == 0
                    and not authenticated_invalid_deployment[
                        "transaction_known_after"
                    ]
                ),
                "authenticated_invalid_bridge_reached_verifier_without_admission": (
                    all(
                        "error" in response
                        for response in authenticated_invalid_bridge["responses"]
                    )
                    and authenticated_invalid_bridge["verifier_acquired_after"]
                    == authenticated_invalid_bridge["verifier_acquired_before"]
                    + authenticated_invalid_bridge["attempts"]
                    and authenticated_invalid_bridge["verifier_active_after"] == 0
                    and authenticated_invalid_bridge["pool_count_after"] == 0
                    and not authenticated_invalid_bridge["transaction_known_after"]
                ),
                "one_accepted_one_busy": classifications
                == ["accepted", "verifier_busy"],
                "tip_unchanged_during_unmined_load": (
                    after_load_status["top_block_height"]
                    == baseline_status["top_block_height"]
                    and after_load_status["top_block_hash"]
                    == baseline_status["top_block_hash"]
                ),
                "p2p_async_propagation": transaction_known(
                    relay_node, accepted_transaction_hash
                )
                and relay_after_load_status["top_block_height"]
                == baseline_status["top_block_height"],
                "pending_transfer_conflict_skipped_verifier": (
                    verifier_after_conflict == verifier_before_conflict
                    and prechecks_after_conflict == prechecks_before_conflict + 1
                    and conflict_elapsed <= MAX_PENDING_TRANSFER_CONFLICT_SECONDS
                    and not transaction_known(
                        node, conflicting_transaction["transaction_hash"]
                    )
                ),
                "exact_duplicate_skipped_verifier": (
                    verifier_after_duplicate == verifier_before_duplicate
                    and prechecks_after_duplicate == prechecks_before_duplicate
                    and duplicate_elapsed <= MAX_PENDING_TRANSFER_CONFLICT_SECONDS
                    and pool_count_after_duplicate == 1
                ),
                "post_load_block_progress": final_status["top_block_height"]
                == final_height,
                "post_load_wallet_progress": source_wallet.call("get_onyx_status")[
                    "balance"
                ]
                == 0
                and receiver_wallet.call("get_onyx_status")["balance"]
                == transfer_amount,
                "post_load_supply_conservation": supply_ok,
            }
            report = {
                "schema": SCHEMA,
                "qualification_scope": "local-load-not-release-evidence",
                "revision": args.revision,
                "generated_at": canonical_utc_now(),
                "network": "onyx",
                "raw_load_report": {
                    "path": str(load_report_path),
                    "sha256": hashlib.sha256(load_report_path.read_bytes()).hexdigest(),
                    "schema": load_report.get("schema"),
                    "observed": load_report.get("observed"),
                    "checks": load_report.get("checks"),
                },
                "abandoned_rpc_cleanup": abandoned_rpc_cleanup,
                "authenticated_invalid_proof": authenticated_invalid_proof,
                "authenticated_invalid_deployment": authenticated_invalid_deployment,
                "authenticated_invalid_bridge": authenticated_invalid_bridge,
                "graceful_shutdown": graceful_shutdown,
                "stale_chain_completion": stale_chain_completion,
                "mixed_ingress": mixed_ingress,
                "reciprocal_mixed_ingress": reciprocal_mixed_ingress,
                "transactions": [
                    {
                        "transaction_hash": transaction["transaction_hash"],
                        "bytes": len(bytes.fromhex(transaction["binary_transaction"])),
                    }
                    for transaction in transactions
                ],
                "admission_classifications": classifications,
                "pending_transfer_conflict_precheck": transfer_conflict_precheck,
                "exact_duplicate_precheck": exact_duplicate_precheck,
                "baseline_status": baseline_status,
                "after_load_status": after_load_status,
                "final_status": final_status,
                "baseline_supply_audit": baseline_audit,
                "final_supply_audit": final_audit,
                "relay_final_supply_audit": relay_final_audit,
                "checks": checks,
                "passed": all(checks.values()),
            }
            report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(
                json.dumps(
                    {
                        "report": str(report_path),
                        "raw_load_report": str(load_report_path),
                        "passed": report["passed"],
                        "checks": checks,
                    },
                    sort_keys=True,
                )
            )
            if not report["passed"]:
                return 1
            return 0
        except Exception:
            for process in nodes:
                print(f"\n--- {process.name} log ---\n{process.read_log()}")
            if source_wallet is not None:
                print(
                    f"\n--- {source_wallet.name} log ---\n{source_wallet.read_log()}"
                )
            if receiver_wallet is not None:
                print(
                    f"\n--- {receiver_wallet.name} log ---\n"
                    f"{receiver_wallet.read_log()}"
                )
            raise
        finally:
            if receiver_wallet is not None:
                receiver_wallet.stop()
            if source_wallet is not None:
                source_wallet.stop()
            for process in reversed(nodes):
                process.stop()


if __name__ == "__main__":
    raise SystemExit(main())
