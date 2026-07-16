#!/usr/bin/env python3
"""Process-level fail-closed SOCKS5 qualification for the real bytecoind binary."""

import argparse
import os
import pathlib
import queue
import socket
import subprocess
import tempfile
import threading
import time


ONION_HOST = "a" * 56 + ".onion"


def recv_exact(connection, size):
    data = bytearray()
    while len(data) != size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            raise RuntimeError("SOCKS5 client closed a truncated message")
        data.extend(chunk)
    return bytes(data)


def unused_port():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    return port


class Destination:
    def __init__(self):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.connections = queue.Queue()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                connection, peer = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            connection.settimeout(2)
            try:
                payload = connection.recv(4096)
            except socket.timeout:
                payload = b""
            self.connections.put((peer, payload))
            connection.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)


class SocksServer:
    def __init__(self, mode, relay_port=None):
        self.mode = mode
        self.relay_port = relay_port
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.requests = queue.Queue()
        self.errors = queue.Queue()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def handle(self, connection):
        connection.settimeout(4)
        if recv_exact(connection, 3) != b"\x05\x01\x00":
            raise RuntimeError("daemon did not request SOCKS5 no-authentication")
        connection.sendall(b"\x05\x00")
        header = recv_exact(connection, 4)
        if header[:3] != b"\x05\x01\x00":
            raise RuntimeError("daemon emitted a noncanonical SOCKS5 CONNECT header")
        if header[3] == 1:
            host = socket.inet_ntoa(recv_exact(connection, 4))
        elif header[3] == 3:
            host = recv_exact(connection, recv_exact(connection, 1)[0]).decode("ascii")
        else:
            raise RuntimeError("daemon emitted an unexpected SOCKS5 address type")
        port = int.from_bytes(recv_exact(connection, 2), "big")
        self.requests.put((header[3], host, port))
        if self.mode == "reject":
            connection.sendall(b"\x05\x05\x00\x01\x7f\x00\x00\x01\x00\x00")
            return
        relay = socket.socket()
        # The destination can distinguish the proxy relay from an illegal direct fallback.
        relay.bind(("127.0.0.2", 0))
        relay.connect(("127.0.0.1", self.relay_port))
        connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x02\x00\x00")
        payload = connection.recv(4096)
        if payload:
            relay.sendall(payload)
        relay.close()

    def run(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self.handle(connection)
            except Exception as error:  # surfaced in the main test thread
                self.errors.put(error)
            finally:
                connection.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)


def wait_item(items, process, timeout, description):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return items.get(timeout=0.2)
        except queue.Empty:
            if process.poll() is not None:
                raise RuntimeError(f"bytecoind exited before {description} (exit {process.returncode})")
    raise RuntimeError(f"timed out waiting for {description}")


def launch_daemon(binary, data_dir, proxy_port, target, dns_guard=None, forbidden_host=None):
    command = [
        str(binary),
        "--net=test",
        f"--data-folder={data_dir}",
        f"--p2p-bind-address=127.0.0.1:{unused_port()}",
        f"--bytecoind-bind-address=127.0.0.1:{unused_port()}",
        f"--exclusive-node-address={target}",
        f"--p2p-proxy=127.0.0.1:{proxy_port}",
    ]
    environment = os.environ.copy()
    marker = data_dir / "dns-leak"
    if dns_guard:
        environment["LD_PRELOAD"] = str(dns_guard)
        environment["BYTECOIN_DNS_FORBIDDEN_HOST"] = forbidden_host
        environment["BYTECOIN_DNS_GUARD_MARKER"] = str(marker)
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=environment
    )
    return process, marker


def stop_daemon(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    return process.stdout.read() if process.stdout else ""


def test_successful_numeric_relay(binary, root):
    destination = Destination()
    proxy = SocksServer("relay", destination.port)
    case_dir = root / "success"
    case_dir.mkdir()
    process, _ = launch_daemon(binary, case_dir, proxy.port, f"127.0.0.1:{destination.port}")
    try:
        request = wait_item(proxy.requests, process, 25, "numeric SOCKS5 CONNECT")
        if request != (1, "127.0.0.1", destination.port):
            raise RuntimeError(f"unexpected numeric proxy request: {request!r}")
        peer, payload = wait_item(destination.connections, process, 10, "relayed P2P handshake")
        if peer[0] != "127.0.0.2":
            raise RuntimeError(f"destination observed direct fallback from {peer[0]}")
        if not payload:
            raise RuntimeError("proxied connection carried no P2P handshake")
        if not proxy.errors.empty():
            raise proxy.errors.get()
    finally:
        output = stop_daemon(process)
        proxy.close()
        destination.close()
    print("numeric proxy relay passed")
    return output


def test_rejection_has_no_direct_fallback(binary, root):
    destination = Destination()
    proxy = SocksServer("reject")
    case_dir = root / "reject"
    case_dir.mkdir()
    process, _ = launch_daemon(binary, case_dir, proxy.port, f"127.0.0.1:{destination.port}")
    try:
        request = wait_item(proxy.requests, process, 25, "rejected SOCKS5 CONNECT")
        if request != (1, "127.0.0.1", destination.port):
            raise RuntimeError(f"unexpected rejected proxy request: {request!r}")
        time.sleep(2)
        if not destination.connections.empty():
            peer, _ = destination.connections.get()
            raise RuntimeError(f"proxy rejection fell back directly from {peer[0]}")
        if not proxy.errors.empty():
            raise proxy.errors.get()
    finally:
        output = stop_daemon(process)
        proxy.close()
        destination.close()
    print("proxy rejection remained fail closed")
    return output


def test_onion_has_no_local_dns(binary, dns_guard, root):
    proxy = SocksServer("reject")
    case_dir = root / "onion"
    case_dir.mkdir()
    process, marker = launch_daemon(
        binary, case_dir, proxy.port, f"{ONION_HOST}:18080", dns_guard, ONION_HOST
    )
    try:
        request = wait_item(proxy.requests, process, 25, "onion SOCKS5 CONNECT")
        if request != (3, ONION_HOST, 18080):
            raise RuntimeError(f"onion identity was not preserved through SOCKS5: {request!r}")
        time.sleep(1)
        if marker.exists():
            raise RuntimeError("daemon attempted a forbidden local onion DNS lookup")
        if not proxy.errors.empty():
            raise proxy.errors.get()
    finally:
        output = stop_daemon(process)
        proxy.close()
    print("onion hostname bypassed local DNS")
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bytecoind", required=True, type=pathlib.Path)
    parser.add_argument("--dns-guard", required=True, type=pathlib.Path)
    args = parser.parse_args()
    binary = args.bytecoind.resolve()
    dns_guard = args.dns_guard.resolve()
    if not binary.is_file() or not dns_guard.is_file():
        raise SystemExit("bytecoind and dns_guard must both exist")
    with tempfile.TemporaryDirectory(prefix="bytecoin-proxy-process-") as temporary:
        root = pathlib.Path(temporary)
        test_successful_numeric_relay(binary, root)
        test_rejection_has_no_direct_fallback(binary, root)
        test_onion_has_no_local_dns(binary, dns_guard, root)
    print("bytecoind process-level SOCKS5 qualification passed")


if __name__ == "__main__":
    main()
