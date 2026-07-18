#!/usr/bin/env python3
"""Process-level fail-closed qualification for untrusted mining templates."""

import argparse
import http.server
import json
import pathlib
import queue
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request


MINING_ADDRESS = (
    "21mQ7KPdmLbjfpg3Coayi4hZzAEgjeL87QXGeDTHahKeJsvKHc6DoprAJmqU"
    "cLhWTUXtxCL6rQFSwEUe6NZdEoqZNpSq1iC"
)
ZERO_HASH = "00" * 32
NONZERO_HASH = "01" + "00" * 31


def template_response(**overrides):
    response = {
        "difficulty": 1,
        "height": 9_000_000,
        "reserved_offset": 0,
        "blocktemplate_blob": "00",
        "status": "OK",
        "top_block_hash": NONZERO_HASH,
        "transaction_pool_version": 1,
        "previous_block_hash": ZERO_HASH,
        "pow_algorithm": "randomx-v2",
        "pow_seed_hash": NONZERO_HASH,
        "cm_prehash": ZERO_HASH,
        "cm_path": ZERO_HASH,
    }
    response.update(overrides)
    return response


class MockDaemon:
    def __init__(self, response):
        self.response = response
        self.methods = queue.Queue()
        self.template_requests = 0
        self.submit_requests = 0
        self.lock = threading.Lock()
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                request = json.loads(self.rfile.read(length).decode("utf-8"))
                method = request.get("method")
                owner.methods.put(method)
                with owner.lock:
                    if method == "get_block_template":
                        owner.template_requests += 1
                    elif method == "submit_block":
                        owner.submit_requests += 1
                if method == "get_currency_id":
                    result = {"currency_id_blob": NONZERO_HASH}
                elif method == "get_block_template":
                    result = owner.response
                else:
                    result = {}
                body = json.dumps(
                    {"jsonrpc": "2.0", "id": request.get("id"), "result": result},
                    separators=(",", ":"),
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def log_message(self, _format, *_args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    return process.stdout.read() if process.stdout else ""


def unused_port():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    return port


def wait_for_port(process, port, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"bytecoind exited during startup (exit {process.returncode})")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("timed out waiting for bytecoind RPC startup")


def rpc_call(port, method, params):
    body = json.dumps(
        {"jsonrpc": "2.0", "id": method, "method": method, "params": params},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/json_rpc",
        data=body,
        headers={"Content-Type": "application/json-rpc"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        decoded = json.loads(response.read().decode("utf-8"))
    if "error" in decoded:
        raise RuntimeError(f"{method} failed: {decoded['error']}")
    return decoded["result"]


def run_valid_daemon_case(minerd, bytecoind):
    valid_template = None
    with tempfile.TemporaryDirectory(prefix="bytecoin-miner-template-") as temporary:
        data_dir = pathlib.Path(temporary)
        rpc_port = unused_port()
        daemon = subprocess.Popen(
            [
                str(bytecoind),
                "--net=test",
                f"--data-folder={data_dir}",
                f"--p2p-bind-address=127.0.0.1:{unused_port()}",
                f"--bytecoind-bind-address=127.0.0.1:{rpc_port}",
                f"--exclusive-node-address=127.0.0.1:{unused_port()}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_for_port(daemon, rpc_port, 30)
            valid_template = rpc_call(
                rpc_port,
                "get_block_template",
                {
                    "reserve_size": 0,
                    "wallet_address": MINING_ADDRESS,
                    "miner_secret": ZERO_HASH,
                },
            )
            miner_data = data_dir / "miner"
            miner_data.mkdir()
            miner = subprocess.Popen(
                [
                    str(minerd),
                    "--net=test",
                    f"--data-folder={miner_data}",
                    f"--bytecoind-address=127.0.0.1:{rpc_port}",
                    f"--wallet-address={MINING_ADDRESS}",
                    "--threads=1",
                    "--limit=1",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                output, _ = miner.communicate(timeout=45)
            except subprocess.TimeoutExpired:
                output = stop_process(miner)
                raise RuntimeError(f"real-daemon miner did not submit a block\n{output}")
            if miner.returncode != 0:
                raise RuntimeError(f"real-daemon miner exited {miner.returncode}\n{output}")
            if "Miner received getblocktemplate" not in output or "Block submitted" not in output:
                raise RuntimeError(f"real-daemon positive template path was incomplete\n{output}")
            if "Rejected block template" in output:
                raise RuntimeError(f"real daemon produced a template rejected by the miner\n{output}")
        finally:
            stop_process(daemon)
    print("real daemon template validation and block submission passed")
    return valid_template


def run_case(binary, name, response, expected_fragment, boast=None):
    daemon = MockDaemon(response)
    temporary = tempfile.TemporaryDirectory(prefix="bytecoin-miner-corrupt-")
    command = [
        str(binary),
        "--net=test",
        f"--data-folder={temporary.name}",
        f"--bytecoind-address=127.0.0.1:{daemon.port}",
        f"--wallet-address={MINING_ADDRESS}",
        "--threads=1",
        "--randomx-light",
        "--limit=1",
    ]
    if boast is not None:
        command.append(f"--boast={boast}")
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    deadline = time.monotonic() + 12
    try:
        while time.monotonic() < deadline:
            with daemon.lock:
                requests = daemon.template_requests
                submissions = daemon.submit_requests
            if submissions:
                raise RuntimeError(f"{name}: miner submitted work derived from a corrupt template")
            if process.poll() is not None:
                raise RuntimeError(f"{name}: miner exited while rejecting corrupt work")
            if requests >= 2:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"{name}: miner did not reject and retry the corrupt template")
    finally:
        output = stop_process(process)
        daemon.close()
        temporary.cleanup()
    if "Miner received getblocktemplate" in output or "Miner found" in output:
        raise RuntimeError(f"{name}: miner activated hashing for corrupt work\n{output}")
    expected = f"Rejected block template: {expected_fragment}"
    if expected not in output:
        raise RuntimeError(f"{name}: missing rejection diagnostic {expected!r}\n{output}")
    print(f"{name}: fail-closed rejection and retry passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--minerd", required=True, type=pathlib.Path)
    parser.add_argument("--bytecoind", required=True, type=pathlib.Path)
    args = parser.parse_args()
    binary = args.minerd.resolve()
    bytecoind = args.bytecoind.resolve()
    if not binary.is_file() or not bytecoind.is_file():
        raise SystemExit("minerd and bytecoind binaries must both exist")

    valid_template = run_valid_daemon_case(binary, bytecoind)
    wrong_parent = dict(valid_template)
    wrong_parent["top_block_hash"] = "02" + "00" * 31
    run_case(binary, "parent mismatch", wrong_parent, "template parent does not match top_block_hash")
    wrong_height = dict(valid_template)
    wrong_height["height"] = valid_template["height"] + 1
    run_case(binary, "coinbase height mismatch", wrong_height, "template coinbase height does not match")
    algorithm_downgrade = dict(valid_template)
    algorithm_downgrade["pow_algorithm"] = "randomx-v2"
    algorithm_downgrade["pow_seed_hash"] = NONZERO_HASH
    run_case(
        binary,
        "algorithm activation mismatch",
        algorithm_downgrade,
        "proof-of-work algorithm does not match template version and height",
    )
    misplaced_seed = dict(valid_template)
    misplaced_seed["pow_seed_hash"] = NONZERO_HASH
    run_case(
        binary,
        "seed on CryptoNight template",
        misplaced_seed,
        "CryptoNight template carries an unexpected RandomX seed",
    )
    run_case(
        binary,
        "unknown algorithm",
        template_response(pow_algorithm="randomx-v3"),
        "unsupported proof-of-work algorithm",
    )
    run_case(binary, "zero difficulty", template_response(difficulty=0), "zero mining difficulty")
    run_case(
        binary,
        "zero candidate height",
        template_response(height=0),
        "candidate height is out of bounds",
    )
    run_case(
        binary,
        "zero top block hash",
        template_response(top_block_hash=ZERO_HASH),
        "top block hash is zero",
    )
    run_case(
        binary,
        "empty block template",
        template_response(blocktemplate_blob=""),
        "block template size is out of bounds",
    )
    run_case(
        binary,
        "missing RandomX seed",
        template_response(pow_seed_hash=ZERO_HASH),
        "RandomX seed hash is zero",
    )
    run_case(
        binary,
        "reserved range overflow",
        template_response(reserved_offset=1),
        "reserved nonce range is outside the block template",
        boast="qualification",
    )
    run_case(
        binary,
        "malformed canonical block",
        template_response(),
        "Error while serializing binary object",
    )
    print("minerd corrupt-template process qualification passed")


if __name__ == "__main__":
    main()
