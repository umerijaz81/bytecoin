#!/usr/bin/env python3
"""Real valid-proof load and post-load liveness qualification for an Onyx daemon."""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import time

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
        transaction_known,
        unused_port,
        wait_until,
    )


SCHEMA = "bytecoin-onyx-verifier-load-process-v1"
ROOT = pathlib.Path(__file__).resolve().parents[2]
LOAD_TOOL = ROOT / "tools" / "onyx_verifier_load.py"
MAX_PENDING_TRANSFER_CONFLICT_SECONDS = 30.0


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

            transaction_paths = []
            for index, transaction in enumerate(transactions):
                path = root / f"valid-load-{index}.json"
                write_transaction(path, transaction)
                transaction_paths.append(path)

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
            final_height = funded_height + 1
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
