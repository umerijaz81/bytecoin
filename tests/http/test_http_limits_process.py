#!/usr/bin/env python3
"""Process-level qualification for HTTP request and connection resource limits."""

import argparse
import json
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.request


MAX_REQUEST_BODY_SIZE = 4 * 1024 * 1024
MAX_HEADER_SIZE = 32 * 1024
MAX_INCOMING_CONNECTIONS = 128
HEADER_TIMEOUT_SECONDS = 5


def unused_port():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    return port


def rpc_body():
    return json.dumps(
        {"jsonrpc": "2.0", "id": "status", "method": "get_status", "params": {}},
        separators=(",", ":"),
    ).encode("ascii")


def http_request(body, extra_headers=b""):
    return (
        b"POST /json_rpc HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Type: application/json-rpc\r\n"
        + extra_headers
        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
        + body
    )


def rpc_status(port):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/json_rpc",
        data=rpc_body(),
        headers={"Content-Type": "application/json-rpc"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        decoded = json.loads(response.read().decode("utf-8"))
    if "result" not in decoded:
        raise RuntimeError(f"unexpected status response: {decoded}")
    return decoded["result"]


def wait_for_rpc(process, port, timeout=30):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"bytecoind exited during startup ({process.returncode})")
        try:
            return rpc_status(port)
        except Exception as error:
            last_error = error
            time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for bytecoind RPC: {last_error}")


def read_response(sock, timeout=5):
    sock.settimeout(timeout)
    chunks = []
    while True:
        try:
            chunk = sock.recv(65536)
        except ConnectionResetError:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def assert_alive(process, port):
    if process.poll() is not None:
        raise RuntimeError(f"bytecoind exited unexpectedly ({process.returncode})")
    rpc_status(port)


def test_oversized_body(process, port):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        request = (
            b"POST /json_rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            + f"Content-Length: {MAX_REQUEST_BODY_SIZE + 1}\r\n\r\n".encode("ascii")
        )
        sock.sendall(request)
        response = read_response(sock)
    if b" 413 Payload Too Large\r\n" not in response:
        raise RuntimeError(f"oversized HTTP body was not rejected with 413: {response[:200]!r}")
    assert_alive(process, port)
    print("oversized declared HTTP body rejected before allocation")


def test_oversized_header(process, port):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        request = b"POST /json_rpc HTTP/1.1\r\nX-Fill: " + b"a" * MAX_HEADER_SIZE + b"\r\n"
        sock.sendall(request)
        response = read_response(sock)
    if response:
        raise RuntimeError(f"oversized HTTP header was not fail-closed: {response[:200]!r}")
    assert_alive(process, port)
    print("oversized streaming HTTP header rejected without process growth")


def test_duplicate_content_length(process, port):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(
            b"POST /json_rpc HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Content-Length: 0\r\nContent-Length: 1\r\n\r\n"
        )
        response = read_response(sock)
    if response:
        raise RuntimeError(f"ambiguous Content-Length request was not rejected: {response[:200]!r}")
    assert_alive(process, port)
    print("duplicate Content-Length request rejected")


def test_connection_cap(process, port):
    idle = []
    overflow = None
    try:
        for _ in range(MAX_INCOMING_CONNECTIONS):
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            sock.sendall(b"P")  # Hold one parser/client allocation without completing a request.
            idle.append(sock)
        time.sleep(0.5)

        overflow = socket.create_connection(("127.0.0.1", port), timeout=5)
        overflow.sendall(http_request(rpc_body()))
        overflow.settimeout(0.75)
        try:
            early = overflow.recv(1)
        except socket.timeout:
            early = b""
        if early:
            raise RuntimeError("HTTP server accepted more than the configured live-client cap")

        idle.pop().close()
        response = read_response(overflow, timeout=5)
        if b" 200 OK\r\n" not in response:
            raise RuntimeError(f"HTTP accept did not resume after a client slot opened: {response[:200]!r}")
        overflow.close()
        overflow = None
    finally:
        if overflow is not None:
            overflow.close()
        for sock in idle:
            sock.close()
    time.sleep(0.2)
    assert_alive(process, port)
    print("live HTTP connection cap and accept-resume behavior passed")


def test_header_timeout(process, port):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        started = time.monotonic()
        sock.sendall(b"P")
        response = read_response(sock, timeout=HEADER_TIMEOUT_SECONDS + 3)
        elapsed = time.monotonic() - started
    if response:
        raise RuntimeError(f"timed-out partial header produced a response: {response[:200]!r}")
    if elapsed < HEADER_TIMEOUT_SECONDS - 1:
        raise RuntimeError(f"partial header connection closed before its deadline ({elapsed:.2f}s)")
    assert_alive(process, port)
    print("partial HTTP header closed at the bounded request deadline")


def run(binary):
    with tempfile.TemporaryDirectory(prefix="bytecoin-http-limits-") as temporary:
        root = pathlib.Path(temporary)
        data = root / "node"
        data.mkdir()
        rpc_port = unused_port()
        output_path = root / "bytecoind.log"
        with output_path.open("w+", encoding="utf-8") as output:
            process = subprocess.Popen(
                [
                    str(binary),
                    "--net=test",
                    f"--data-folder={data}",
                    f"--p2p-bind-address=127.0.0.1:{unused_port()}",
                    f"--bytecoind-bind-address=127.0.0.1:{rpc_port}",
                    f"--exclusive-node-address=127.0.0.1:{unused_port()}",
                ],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                wait_for_rpc(process, rpc_port)
                test_oversized_body(process, rpc_port)
                test_oversized_header(process, rpc_port)
                test_duplicate_content_length(process, rpc_port)
                test_connection_cap(process, rpc_port)
                test_header_timeout(process, rpc_port)
            except Exception:
                output.flush()
                output.seek(0)
                print(output.read())
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bytecoind", required=True, type=pathlib.Path)
    args = parser.parse_args()
    binary = args.bytecoind.resolve()
    if not binary.is_file():
        parser.error(f"binary does not exist: {binary}")
    run(binary)


if __name__ == "__main__":
    main()
