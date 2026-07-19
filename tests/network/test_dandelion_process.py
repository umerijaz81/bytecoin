#!/usr/bin/env python3
"""Socket-level Dandelion++ relay qualification with real node and wallet processes."""

import argparse
import base64
import json
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


WALLET_PASSWORD = "process-test-wallet-password"
WALLET_AUTH = "process-test:process-test-password"


def unused_port():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    return port


def rpc_call(port, method, params=None, authorization=None, timeout=10):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": method, "method": method, "params": params or {}},
        separators=(",", ":"),
    ).encode("utf-8")
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
    with urllib.request.urlopen(request, timeout=timeout) as response:
        decoded = json.loads(response.read().decode("utf-8"))
    if "error" in decoded:
        raise RuntimeError(f"{method} failed: {decoded['error']}")
    return decoded["result"]


class Process:
    def __init__(self, name, command, output_directory, stdin=None):
        self.name = name
        self.output_path = output_directory / f"{name}.log"
        self.output = self.output_path.open("w+", encoding="utf-8")
        self.process = subprocess.Popen(
            [str(part) for part in command],
            stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=self.output,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if stdin is not None:
            self.process.stdin.write(stdin)
            self.process.stdin.close()

    def check(self):
        if self.process.poll() is not None:
            raise RuntimeError(
                f"{self.name} exited unexpectedly ({self.process.returncode})\n{self.read_output()}"
            )

    def read_output(self):
        self.output.flush()
        self.output.seek(0)
        return self.output.read()

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.output.close()


def wait_until(description, predicate, processes, timeout=30, interval=0.1):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        for process in processes:
            process.check()
        try:
            result = predicate()
            if result:
                return result
        except (OSError, RuntimeError, urllib.error.URLError) as error:
            last_error = error
        time.sleep(interval)
    suffix = f": {last_error}" if last_error else ""
    raise RuntimeError(f"timed out waiting for {description}{suffix}")


def node_status(port):
    return rpc_call(port, "get_status")


def pool_hashes(port):
    result = rpc_call(port, "sync_mem_pool", {"known_hashes": []})
    return {transaction["hash"] for transaction in result["added_transactions"]}


def wait_for_pool(name, port, transaction_hash, processes, timeout):
    return wait_until(
        f"{transaction_hash} in {name} mempool",
        lambda: transaction_hash in pool_hashes(port),
        processes,
        timeout=timeout,
    )


def assert_pool_absent(name, port, transaction_hash):
    if transaction_hash in pool_hashes(port):
        raise RuntimeError(f"{name} received {transaction_hash} before the expected fluff transition")


def start_node(binary, root, name, p2p_port, rpc_port, exclusive_port, extra=None):
    data = root / name
    data.mkdir()
    command = [
        binary,
        "--net=test",
        f"--data-folder={data}",
        f"--p2p-bind-address=127.0.0.1:{p2p_port}",
        f"--bytecoind-bind-address=127.0.0.1:{rpc_port}",
        f"--exclusive-node-address=127.0.0.1:{exclusive_port}",
    ]
    command.extend(extra or [])
    process = Process(name, command, root)
    wait_until(
        f"{name} RPC startup",
        lambda: node_status(rpc_port),
        [process],
        timeout=30,
    )
    return process


def create_wallet(walletd, root):
    mnemonic_result = subprocess.run(
        [str(walletd), "--create-mnemonic", "--mnemonic-strength=128"],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    mnemonic_lines = [line.strip() for line in mnemonic_result.stdout.splitlines() if line.strip()]
    if not mnemonic_lines:
        raise RuntimeError("walletd did not produce a mnemonic")
    mnemonic = mnemonic_lines[-1]
    wallet_file = root / "relay.wallet"
    wallet_data = root / "wallet-data"
    wallet_data.mkdir()
    creation_input = f"{mnemonic}\n\n{WALLET_PASSWORD}\n{WALLET_PASSWORD}\n"
    created = subprocess.run(
        [
            str(walletd),
            "--net=test",
            f"--data-folder={wallet_data}",
            f"--wallet-file={wallet_file}",
            "--create-wallet",
            "--wallet-type=amethyst",
            "--address-count=2",
            "--creation-timestamp=0",
        ],
        input=creation_input,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if created.returncode != 0:
        raise RuntimeError(f"wallet creation failed\n{created.stdout}\n{created.stderr}")
    return wallet_file, wallet_data


def launch_wallet(walletd, root, wallet_file, wallet_data, wallet_port, origin_rpc):
    auth_file = root / "walletd.auth"
    auth_file.write_text(WALLET_AUTH + "\n", encoding="utf-8")
    auth_file.chmod(0o600)
    process = Process(
        "walletd",
        [
            walletd,
            "--net=test",
            f"--data-folder={wallet_data}",
            f"--wallet-file={wallet_file}",
            f"--wallet-password={WALLET_PASSWORD}",
            f"--walletd-http-auth-file={auth_file}",
            f"--walletd-bind-address=127.0.0.1:{wallet_port}",
            f"--bytecoind-remote-address=127.0.0.1:{origin_rpc}",
        ],
        root,
    )
    wait_until(
        "wallet RPC startup",
        lambda: rpc_call(wallet_port, "get_status", authorization=WALLET_AUTH),
        [process],
        timeout=30,
    )
    return process


def mine_blocks(minerd, root, rpc_port, wallet_address, count):
    miner_data = root / "miner"
    miner_data.mkdir()
    result = subprocess.run(
        [
            str(minerd),
            "--net=test",
            f"--data-folder={miner_data}",
            f"--bytecoind-address=127.0.0.1:{rpc_port}",
            f"--wallet-address={wallet_address}",
            "--threads=1",
            f"--limit={count}",
        ],
        capture_output=True,
        text=True,
        timeout=90,
    )
    if result.returncode != 0 or result.stdout.count("Block submitted") < count:
        raise RuntimeError(f"mining {count} qualification blocks failed\n{result.stdout}\n{result.stderr}")


def create_transaction(wallet_port, recipient, change_address):
    result = rpc_call(
        wallet_port,
        "create_transaction",
        {
            "transaction": {
                "anonymity": 0,
                "payment_id": "",
                "transfers": [{"address": recipient, "amount": 100000}],
            },
            "any_spend_address": True,
            "change_address": change_address,
            "confirmed_height_or_depth": -1,
            "fee_per_byte": 1,
            "optimization": "minimal",
        },
        authorization=WALLET_AUTH,
    )
    return result["transaction"]["hash"], result["binary_transaction"]


def send_from_wallet(wallet_port, binary_transaction):
    result = rpc_call(
        wallet_port,
        "send_transaction",
        {"binary_transaction": binary_transaction},
        authorization=WALLET_AUTH,
    )
    if result["send_result"] != "broadcast":
        raise RuntimeError(f"wallet returned unexpected send result: {result}")


def reject_invalid_policy(binary, root, option, expected):
    data = root / f"invalid-{len(list(root.glob('invalid-*')))}"
    data.mkdir()
    result = subprocess.run(
        [str(binary), "--net=test", f"--data-folder={data}", option],
        capture_output=True,
        text=True,
        timeout=15,
    )
    output = result.stdout + result.stderr
    if result.returncode == 0 or expected not in output:
        raise RuntimeError(f"invalid policy option was not rejected: {option}\n{output}")


def run(args):
    processes = []
    with tempfile.TemporaryDirectory(prefix="bytecoin-dandelion-process-") as temporary:
        root = pathlib.Path(temporary)
        reject_invalid_policy(
            args.bytecoind,
            root,
            "--dandelion-fluff-probability=101",
            "must be in range 0..100",
        )
        reject_invalid_policy(
            args.bytecoind,
            root,
            "--dandelion-embargo-min-seconds=601",
            "must be in range 1..600",
        )
        reject_invalid_policy(
            args.bytecoind,
            root,
            "--dandelion-embargo-min-seconds=31",
            "cannot exceed --dandelion-embargo-max-seconds",
        )

        wallet_file, wallet_data = create_wallet(args.walletd, root)
        ports = {name: unused_port() for name in (
            "a_p2p", "a_rpc", "b_p2p", "b_rpc", "c_p2p", "c_rpc",
            "v4_p2p", "v4_rpc", "wallet_rpc", "dummy",
        )}
        try:
            node_b = start_node(
                args.bytecoind, root, "node-b-reflector", ports["b_p2p"], ports["b_rpc"],
                ports["dummy"], ["--disable-dandelion"],
            )
            processes.append(node_b)
            node_a = start_node(
                args.bytecoind, root, "node-a-origin", ports["a_p2p"], ports["a_rpc"],
                ports["b_p2p"], [
                    "--dandelion-fluff-probability=0",
                    "--dandelion-embargo-min-seconds=8",
                    "--dandelion-embargo-max-seconds=8",
                ],
            )
            processes.append(node_a)
            node_c = start_node(
                args.bytecoind, root, "node-c-observer", ports["c_p2p"], ports["c_rpc"],
                ports["a_p2p"],
            )
            processes.append(node_c)
            node_v4 = start_node(
                args.v4_bytecoind, root, "node-v4-observer", ports["v4_p2p"], ports["v4_rpc"],
                ports["a_p2p"],
            )
            processes.append(node_v4)

            wait_until(
                "isolated relay topology",
                lambda: (
                    node_status(ports["a_rpc"])["outgoing_peer_count"] == 1
                    and node_status(ports["a_rpc"])["incoming_peer_count"] >= 2
                    and node_status(ports["b_rpc"])["incoming_peer_count"] >= 1
                    and node_status(ports["v4_rpc"])["outgoing_peer_count"] == 1
                    and "Handshake request version=4" in node_a.read_output()
                ),
                processes,
                timeout=30,
            )

            wallet = launch_wallet(
                args.walletd, root, wallet_file, wallet_data, ports["wallet_rpc"], ports["a_rpc"]
            )
            processes.append(wallet)
            addresses = rpc_call(
                ports["wallet_rpc"], "get_addresses", authorization=WALLET_AUTH
            )["addresses"]
            if len(addresses) < 2:
                raise RuntimeError("qualification wallet did not contain two addresses")

            mine_blocks(args.minerd, root, ports["a_rpc"], addresses[0], 15)
            for name in ("a", "b", "c", "v4"):
                rpc_port = ports[f"{name}_rpc"]
                wait_until(
                    f"node {name} chain synchronization",
                    lambda rpc_port=rpc_port: node_status(rpc_port)["top_block_height"] >= 15,
                    processes,
                    timeout=45,
                )
            wait_until(
                "wallet chain synchronization",
                lambda: rpc_call(
                    ports["wallet_rpc"], "get_status", authorization=WALLET_AUTH
                )["top_block_height"] >= 15,
                processes,
                timeout=45,
            )

            tx1_hash, tx1_binary = create_transaction(ports["wallet_rpc"], addresses[1], addresses[0])
            assert_pool_absent("node C", ports["c_rpc"], tx1_hash)
            sent_at = time.monotonic()
            send_from_wallet(ports["wallet_rpc"], tx1_binary)
            wait_for_pool("node B", ports["b_rpc"], tx1_hash, processes, timeout=4)
            while time.monotonic() - sent_at < 5:
                assert_pool_absent("node C", ports["c_rpc"], tx1_hash)
                time.sleep(0.1)
            wait_for_pool("node C", ports["c_rpc"], tx1_hash, processes, timeout=7)
            if time.monotonic() - sent_at < 7:
                raise RuntimeError("node C received reflected fluff before the configured embargo")
            print("stem routing, reflected-fluff loop resistance, and embargo recovery passed")

            tx2_hash, tx2_binary = create_transaction(ports["wallet_rpc"], addresses[1], addresses[0])
            sent_at = time.monotonic()
            send_from_wallet(ports["wallet_rpc"], tx2_binary)
            wait_for_pool("node B", ports["b_rpc"], tx2_hash, processes, timeout=4)
            assert_pool_absent("node C", ports["c_rpc"], tx2_hash)
            node_b.stop()
            processes.remove(node_b)
            wait_for_pool("node C", ports["c_rpc"], tx2_hash, processes, timeout=4)
            if time.monotonic() - sent_at >= 7:
                raise RuntimeError("stem-peer disconnect did not recover before the embargo")
            print("stem-peer disconnect recovery passed")

            tx3_hash, tx3_binary = create_transaction(ports["wallet_rpc"], addresses[1], addresses[0])
            assert_pool_absent("node v4", ports["v4_rpc"], tx3_hash)
            assert_pool_absent("node C", ports["c_rpc"], tx3_hash)
            sent_at = time.monotonic()
            send_from_wallet(ports["wallet_rpc"], tx3_binary)
            wait_for_pool("node v4", ports["v4_rpc"], tx3_hash, processes, timeout=4)
            wait_for_pool("node C", ports["c_rpc"], tx3_hash, processes, timeout=4)
            if time.monotonic() - sent_at >= 4:
                raise RuntimeError("protocol-v4 compatibility diffusion was delayed by a stem embargo")
            print("negotiated protocol-v4 immediate-diffusion fallback passed")
        except Exception:
            for process in processes:
                try:
                    print(f"\n--- {process.name} ---\n{process.read_output()}")
                except Exception:
                    pass
            raise
        finally:
            for process in reversed(processes):
                process.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bytecoind", required=True, type=pathlib.Path)
    parser.add_argument("--v4-bytecoind", required=True, type=pathlib.Path)
    parser.add_argument("--walletd", required=True, type=pathlib.Path)
    parser.add_argument("--minerd", required=True, type=pathlib.Path)
    args = parser.parse_args()
    args.bytecoind = args.bytecoind.resolve()
    args.v4_bytecoind = args.v4_bytecoind.resolve()
    args.walletd = args.walletd.resolve()
    args.minerd = args.minerd.resolve()
    for binary in (args.bytecoind, args.v4_bytecoind, args.walletd, args.minerd):
        if not binary.is_file():
            parser.error(f"binary does not exist: {binary}")
    run(args)


if __name__ == "__main__":
    main()
