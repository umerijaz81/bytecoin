#!/usr/bin/env python3
"""Crash a real Onyx daemon inside block apply/reorg transactions and verify recovery."""

import argparse
import hashlib
import json
import pathlib
import shutil
import sqlite3
import subprocess
import tempfile
from datetime import datetime, timezone

try:
    from .test_onyx_qualification_process import (
        MINING_ADDRESS_A,
        WALLET_PASSWORD,
        Node,
        WalletProcess,
        create_wallet,
        mine_blocks,
        rpc_call,
        transaction_known,
        unused_port,
        wait_until,
    )
except ImportError:
    from test_onyx_qualification_process import (
        MINING_ADDRESS_A,
        WALLET_PASSWORD,
        Node,
        WalletProcess,
        create_wallet,
        mine_blocks,
        rpc_call,
        transaction_known,
        unused_port,
        wait_until,
    )


SCHEMA = "bytecoin-onyx-daemon-crash-v1"
CRASH_CODES = {
    "apply-after-state-write": 91,
    "apply-before-commit": 92,
    "apply-after-commit": 93,
    "reorg-after-undo": 94,
    "reorg-before-commit": 95,
    "reorg-after-commit": 96,
}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def clone_data(source, destination):
    shutil.copytree(source, destination)


def onyx_rows(data):
    database = data / "blockchain.sqlite"
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    try:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        rows = connection.execute(
            "SELECT kk, vv FROM kv_table WHERE kk = ? OR substr(kk, 1, 1) = ? ORDER BY kk",
            (b"Z", b"z"),
        ).fetchall()
    finally:
        connection.close()
    if integrity != "ok":
        raise RuntimeError(f"SQLite integrity check failed for {database}: {integrity}")
    return {
        "integrity": integrity,
        "rows": [
            {
                "key_hex": key.hex(),
                "value_sha256": hashlib.sha256(value).hexdigest(),
                "value_size": len(value),
            }
            for key, value in rows
        ],
    }


def node(binary, root, name, data, point="disabled", exclusive_port=None):
    return Node(
        binary,
        root,
        name,
        "onyx",
        unused_port(),
        unused_port(),
        exclusive_port=exclusive_port,
        data=data,
        extra_args=[f"--onyx-crash-test-point={point}"],
    )


def close_expected_crash(subject, point, timeout=1800):
    expected = CRASH_CODES[point]
    try:
        actual = subject.process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"{point} daemon did not reach its crash point") from error
    log = subject.read_log()
    marker = f"ONYX_CRASH_TEST_POINT={point} exit={expected}"
    subject.log.close()
    if actual != expected or marker not in log:
        raise RuntimeError(
            f"{point} exited {actual}, expected {expected}, marker={marker!r}\n{log}"
        )
    return {"point": point, "return_code": actual, "marker": marker}


def mine_while_daemon_crashes(minerd, root, name, subject, count=1):
    miner_data = root / f"{name}-miner-data"
    miner_data.mkdir()
    miner = subprocess.Popen(
        [
            str(minerd),
            "--net=onyx",
            f"--data-folder={miner_data}",
            f"--bytecoind-address=127.0.0.1:{subject.rpc_port}",
            f"--wallet-address={MINING_ADDRESS_A}",
            "--threads=1",
            f"--limit={count}",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return miner


def stop_miner(miner):
    if miner.poll() is None:
        miner.terminate()
        try:
            miner.wait(timeout=5)
        except subprocess.TimeoutExpired:
            miner.kill()
            miner.wait(timeout=5)


def identity(subject):
    return {
        "status": subject.status(),
        "audit": rpc_call(subject.rpc_port, "get_onyx_supply_audit"),
    }


def program_state(subject, program_id, application):
    return rpc_call(
        subject.rpc_port,
        "get_onyx_standard_program_state",
        {"program_id": program_id, "application": application},
    )


def assert_identity(actual, expected, label, exact_tip=True):
    fields = ["top_block_height"]
    if exact_tip:
        fields.append("top_block_hash")
    for field in fields:
        if actual["status"].get(field) != expected["status"].get(field):
            raise RuntimeError(
                f"{label} status differs at {field}: "
                f"{actual['status'].get(field)!r} != {expected['status'].get(field)!r}"
            )
    if actual["audit"] != expected["audit"]:
        raise RuntimeError(
            f"{label} Onyx audit differs: {actual['audit']!r} != {expected['audit']!r}"
        )


def normalized_onyx_rows(document):
    normalized = []
    for row in document["rows"]:
        key = bytes.fromhex(row["key_hex"])
        normalized.append(
            {
                "key_kind": "state" if key == b"Z" else "undo",
                "key_size": len(key),
                "value_sha256": row["value_sha256"],
                "value_size": row["value_size"],
            }
        )
    return normalized


def reopen_and_check(
    binary,
    root,
    name,
    data,
    expected_identity,
    expected_rows,
    exact_tip=True,
    expected_program=None,
):
    subject = node(binary, root, name, data, exclusive_port=unused_port())
    try:
        wait_until(f"{name} recovery RPC", subject.status, [subject], timeout=60)
        actual = identity(subject)
        assert_identity(actual, expected_identity, name, exact_tip=exact_tip)
        actual_program = None
        if expected_program is not None:
            actual_program = program_state(
                subject, expected_program["program_id"], expected_program["application"]
            )
            if actual_program != expected_program["state"]:
                raise RuntimeError(
                    f"{name} program state differs: "
                    f"{actual_program!r} != {expected_program['state']!r}"
                )
    finally:
        subject.stop()
    raw = onyx_rows(data)
    rows_match = raw == expected_rows if exact_tip else (
        raw["integrity"] == expected_rows["integrity"]
        and normalized_onyx_rows(raw) == normalized_onyx_rows(expected_rows)
    )
    if not rows_match:
        raise RuntimeError(f"{name} recovered Onyx rows differ: {raw!r} != {expected_rows!r}")
    result = {"identity": actual, "database": raw}
    if expected_program is not None:
        result["program_state"] = actual_program
    return result


def create_bridge(wallet, memo):
    addresses = wallet.call("get_addresses")["addresses"]
    onyx = wallet.call("get_onyx_status")
    if len(addresses) != 1 or not onyx.get("address"):
        raise RuntimeError("setup wallet did not expose legacy and Onyx addresses")
    unspents = wallet.call(
        "get_unspents", {"address": addresses[0], "height_or_depth": -1}
    )["spendable"]
    output = next((item for item in unspents if item["amount"] > 2), None)
    if output is None:
        raise RuntimeError(f"no bridgeable setup output: {unspents!r}")
    unsigned = wallet.call(
        "create_onyx_bridge",
        {
            "address": onyx["address"],
            "legacy_amount": output["amount"],
            "fee": 1,
            "legacy_stack_index": output["stack_index"],
            "legacy_key_image": output["key_image"],
            "expiry_height": 0,
            "memo": memo,
        },
    )["unsigned_bridge"]
    signature = wallet.call("sign_onyx_bridge", {"unsigned_bridge": unsigned})[
        "ownership_signature"
    ]
    return wallet.call(
        "finalize_onyx_bridge",
        {"unsigned_bridge": unsigned, "ownership_signature": signature},
    )


def write_report(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bytecoind", required=True, type=pathlib.Path)
    parser.add_argument("--walletd", required=True, type=pathlib.Path)
    parser.add_argument("--minerd", required=True, type=pathlib.Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--report", required=True, type=pathlib.Path)
    args = parser.parse_args()
    binary = args.bytecoind.resolve()
    walletd = args.walletd.resolve()
    minerd = args.minerd.resolve()
    for label, executable in (
        ("bytecoind", binary),
        ("walletd", walletd),
        ("minerd", minerd),
    ):
        if not executable.is_file():
            parser.error(f"{label} does not exist: {executable}")

    observations = {}
    crashes = []
    with tempfile.TemporaryDirectory(prefix="bytecoin-onyx-daemon-crash-") as temporary:
        root = pathlib.Path(temporary)
        baseline_data = root / "baseline-data"
        setup = node(binary, root, "baseline", baseline_data)
        wallet = None
        try:
            wait_until("baseline RPC", setup.status, [setup], timeout=60)
            wallet_file, wallet_data = create_wallet(walletd, root, "crash-source")
            wallet = WalletProcess(
                walletd,
                root,
                wallet_file,
                wallet_data,
                unused_port(),
                setup.rpc_port,
                WALLET_PASSWORD,
                name="crash-source-wallet",
            )
            wait_until("setup wallet RPC", wallet.status, [setup, wallet], timeout=60)
            legacy_address = wallet.call("get_addresses")["addresses"][0]
            mine_blocks(minerd, root, "baseline-funding", setup.rpc_port, legacy_address, 3)
            wait_until(
                "setup funding",
                lambda: wallet.status()["top_block_height"] >= 3
                and wallet.call(
                    "get_balance", {"address": "", "height_or_depth": -1}
                )["spendable"]
                > 2,
                [setup, wallet],
                timeout=120,
            )
            bridge = create_bridge(wallet, "daemon crash qualification")
            baseline_identity = identity(setup)
        finally:
            if wallet is not None:
                wallet.stop()
            setup.stop()
        baseline_rows = onyx_rows(baseline_data)

        control_data = root / "control-applied-data"
        clone_data(baseline_data, control_data)
        control = node(binary, root, "control-applied", control_data)
        try:
            wait_until("control apply RPC", control.status, [control], timeout=60)
            rpc_call(
                control.rpc_port,
                "send_transaction",
                {"binary_transaction": bridge["binary_transaction"]},
            )
            wait_until(
                "control bridge pool",
                lambda: transaction_known(control, bridge["transaction_hash"]),
                [control],
                timeout=120,
            )
            mine_blocks(
                minerd,
                root,
                "control-bridge",
                control.rpc_port,
                MINING_ADDRESS_A,
                1,
                timeout=1800,
            )
            wait_until(
                "control bridge apply",
                lambda: control.status()["top_block_height"]
                == baseline_identity["status"]["top_block_height"] + 1,
                [control],
                timeout=120,
            )
            applied_identity = identity(control)
        finally:
            control.stop()
        applied_rows = onyx_rows(control_data)
        if not applied_rows["rows"] or applied_identity["audit"] == baseline_identity["audit"]:
            raise RuntimeError("control bridge did not create distinct committed Onyx state")

        for point in (
            "apply-after-state-write",
            "apply-before-commit",
            "apply-after-commit",
        ):
            scenario_data = root / f"{point}-data"
            clone_data(baseline_data, scenario_data)
            subject = node(binary, root, point, scenario_data, point=point)
            miner = None
            try:
                wait_until(f"{point} RPC", subject.status, [subject], timeout=60)
                rpc_call(
                    subject.rpc_port,
                    "send_transaction",
                    {"binary_transaction": bridge["binary_transaction"]},
                )
                wait_until(
                    f"{point} bridge pool",
                    lambda: transaction_known(subject, bridge["transaction_hash"]),
                    [subject],
                    timeout=120,
                )
                miner = mine_while_daemon_crashes(minerd, root, point, subject)
                crashes.append(close_expected_crash(subject, point))
            finally:
                if miner is not None:
                    stop_miner(miner)
                if subject.process.poll() is None:
                    subject.stop()
            expected_identity = (
                applied_identity if point == "apply-after-commit" else baseline_identity
            )
            expected_rows = applied_rows if point == "apply-after-commit" else baseline_rows
            observations[point] = reopen_and_check(
                binary,
                root,
                f"{point}-recovered",
                scenario_data,
                expected_identity,
                expected_rows,
                exact_tip=point != "apply-after-commit",
            )

        # Build one real deployed and activated NFT program, then fork immediately before its
        # first state transition. Reorganization crashes therefore exercise program state as well
        # as commitment root, supply, undo records, and canonical tip recovery.
        pre_call_data = root / "program-pre-call-data"
        clone_data(control_data, pre_call_data)
        program_builder = node(binary, root, "program-builder", pre_call_data)
        program_wallet = None
        try:
            wait_until("program builder RPC", program_builder.status, [program_builder], timeout=60)
            program_wallet = WalletProcess(
                walletd,
                root,
                wallet_file,
                wallet_data,
                unused_port(),
                program_builder.rpc_port,
                WALLET_PASSWORD,
                name="program-crash-wallet",
            )
            wait_until(
                "program wallet bridge synchronization",
                lambda: program_wallet.status()["top_block_height"]
                >= applied_identity["status"]["top_block_height"]
                and program_wallet.call("get_onyx_status")["balance"]
                == applied_identity["audit"]["circulating_supply"],
                [program_builder, program_wallet],
                timeout=180,
            )
            deployment = program_wallet.call(
                "create_onyx_standard_program_deployment",
                {
                    "kind": "nft",
                    "activation_height": 0,
                    "deactivation_height": 0,
                    "fee": 100000,
                    "expiry_height": 0,
                },
            )
            program_wallet.call(
                "send_transaction",
                {"binary_transaction": deployment["binary_transaction"]},
            )
            mine_blocks(
                minerd,
                root,
                "program-deployment",
                program_builder.rpc_port,
                MINING_ADDRESS_A,
                1,
                timeout=1800,
            )
            deployment_height = applied_identity["status"]["top_block_height"] + 1
            activation_height = deployment_height + 20
            mine_blocks(
                minerd,
                root,
                "program-activation",
                program_builder.rpc_port,
                MINING_ADDRESS_A,
                activation_height - deployment_height,
                timeout=600,
            )
            wait_until(
                "program activation",
                lambda: program_builder.status()["top_block_height"] == activation_height
                and program_wallet.status()["top_block_height"] >= activation_height,
                [program_builder, program_wallet],
                timeout=180,
            )
            nft_application = (
                bytes((1, 1))
                + (21).to_bytes(32, "little")
                + (22).to_bytes(32, "little")
                + bytes((33, 1))
            ).hex()
            pre_call_program = program_state(
                program_builder, deployment["program_id"], nft_application
            )
            if pre_call_program.get("found") or pre_call_program.get("state") != "":
                raise RuntimeError(
                    f"fresh NFT program state was unexpectedly present: {pre_call_program!r}"
                )
            pre_call_identity = identity(program_builder)
        finally:
            if program_wallet is not None:
                program_wallet.stop()
            program_builder.stop()
        pre_call_rows = onyx_rows(pre_call_data)

        stateful_data = root / "program-stateful-data"
        clone_data(pre_call_data, stateful_data)
        stateful = node(binary, root, "program-stateful", stateful_data)
        program_wallet = None
        try:
            wait_until("stateful program RPC", stateful.status, [stateful], timeout=60)
            program_wallet = WalletProcess(
                walletd,
                root,
                wallet_file,
                wallet_data,
                unused_port(),
                stateful.rpc_port,
                WALLET_PASSWORD,
                name="program-stateful-wallet",
            )
            wait_until(
                "stateful program wallet synchronization",
                lambda: program_wallet.status()["top_block_height"] >= activation_height,
                [stateful, program_wallet],
                timeout=120,
            )
            next_state = "8503" + "00" * 30
            state_call = program_wallet.call(
                "create_onyx_standard_program_call",
                {
                    "program_id": deployment["program_id"],
                    "valid_from_height": 0,
                    "expiry_height": 0,
                    "application": nft_application,
                    "prior_state": "dea354729d447a92315a7730a8ffa9c2621f025a2e73cf2c794b7923939f1a00",
                    "next_state": next_state,
                    "witness": "22" + "00" * 31,
                },
            )
            program_wallet.call(
                "send_transaction",
                {"binary_transaction": state_call["binary_transaction"]},
            )
            mine_blocks(
                minerd,
                root,
                "program-state-call",
                stateful.rpc_port,
                MINING_ADDRESS_A,
                1,
                timeout=1800,
            )
            call_height = activation_height + 1
            wait_until(
                "stateful program call",
                lambda: stateful.status()["top_block_height"] == call_height
                and program_state(stateful, deployment["program_id"], nft_application).get(
                    "state"
                )
                == next_state,
                [stateful, program_wallet],
                timeout=1800,
            )
            stateful_identity = identity(stateful)
            stateful_program = program_state(
                stateful, deployment["program_id"], nft_application
            )
        finally:
            if program_wallet is not None:
                program_wallet.stop()
            stateful.stop()
        stateful_rows = onyx_rows(stateful_data)

        alternate_data = root / "alternate-data"
        clone_data(pre_call_data, alternate_data)
        alternate = node(binary, root, "alternate-build", alternate_data)
        try:
            wait_until("alternate build RPC", alternate.status, [alternate], timeout=60)
            mine_blocks(
                minerd,
                root,
                "alternate-two-blocks",
                alternate.rpc_port,
                MINING_ADDRESS_A,
                2,
            )
            wait_until(
                "alternate branch height",
                lambda: alternate.status()["top_block_height"]
                == pre_call_identity["status"]["top_block_height"] + 2,
                [alternate],
                timeout=60,
            )
            alternate_identity = identity(alternate)
            alternate_program = program_state(
                alternate, deployment["program_id"], nft_application
            )
        finally:
            alternate.stop()
        alternate_rows = onyx_rows(alternate_data)
        if alternate_rows != pre_call_rows:
            raise RuntimeError("empty alternate branch unexpectedly changed Onyx rows")

        alternate_server = node(binary, root, "alternate-server", alternate_data)
        try:
            wait_until("alternate server RPC", alternate_server.status, [alternate_server], timeout=60)
            alternate_p2p = unused_port()
            # Restart the server on a known P2P port used by every isolated reorg scenario.
            alternate_server.stop()
            alternate_server = Node(
                binary,
                root,
                "alternate-server-fixed",
                "onyx",
                alternate_p2p,
                unused_port(),
                data=alternate_data,
                extra_args=["--onyx-crash-test-point=disabled"],
            )
            wait_until("fixed alternate server RPC", alternate_server.status, [alternate_server], timeout=60)

            for point in (
                "reorg-after-undo",
                "reorg-before-commit",
                "reorg-after-commit",
            ):
                scenario_data = root / f"{point}-data"
                clone_data(stateful_data, scenario_data)
                subject = node(
                    binary,
                    root,
                    point,
                    scenario_data,
                    point=point,
                    exclusive_port=alternate_p2p,
                )
                try:
                    crashes.append(close_expected_crash(subject, point))
                finally:
                    if subject.process.poll() is None:
                        subject.stop()
                expected_identity = (
                    alternate_identity if point == "reorg-after-commit" else stateful_identity
                )
                expected_rows = (
                    alternate_rows if point == "reorg-after-commit" else stateful_rows
                )
                expected_program_state = (
                    alternate_program if point == "reorg-after-commit" else stateful_program
                )
                observations[point] = reopen_and_check(
                    binary,
                    root,
                    f"{point}-recovered",
                    scenario_data,
                    expected_identity,
                    expected_rows,
                    expected_program={
                        "program_id": deployment["program_id"],
                        "application": nft_application,
                        "state": expected_program_state,
                    },
                )
        finally:
            alternate_server.stop()

    report = {
        "schema": SCHEMA,
        "scope": "local-full-daemon-crash-not-release-evidence",
        "revision": args.revision,
        "generated_at": utc_now(),
        "passed": True,
        "crashes": crashes,
        "checks": {point: True for point in CRASH_CODES},
        "control": {
            "baseline": baseline_identity,
            "applied": applied_identity,
            "alternate": alternate_identity,
            "program_pre_call": pre_call_identity,
            "program_stateful": stateful_identity,
            "program_pre_call_state": pre_call_program,
            "program_stateful_state": stateful_program,
            "alternate_program_state": alternate_program,
            "baseline_database": baseline_rows,
            "applied_database": applied_rows,
            "alternate_database": alternate_rows,
            "program_pre_call_database": pre_call_rows,
            "program_stateful_database": stateful_rows,
        },
        "observed": observations,
    }
    write_report(args.report.resolve(), report)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
