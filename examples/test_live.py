#!/usr/bin/env python3
"""Smoke-test a live IDA Code Mode GUI or idalib endpoint."""

import argparse
import gzip
from http.client import HTTPConnection
import json
import os
import queue
import threading
import time
from urllib.parse import urlsplit

from ida_codemode.registry import discover_instances, get_registry_dir


class CheckFailed(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise CheckFailed(message)


def request(endpoint, token, method, path, payload=None, *, compressed=False):
    parsed = urlsplit(endpoint)
    body = None if payload is None else json.dumps(payload).encode()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
        if compressed:
            body = gzip.compress(body)
            headers["Content-Encoding"] = "gzip"
    connection = HTTPConnection(parsed.hostname, parsed.port, timeout=120)
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response.status, json.loads(data)


def discover_token(endpoint, registry_dir):
    port = urlsplit(endpoint).port
    valid, unavailable = discover_instances(registry_dir)
    matches = [entry for entry in valid if entry["port"] == port]
    if len(matches) != 1:
        raise CheckFailed(f"expected one valid registry entry for port {port}")
    return matches[0]["token"]


def run(endpoint, token, *, save=False, close=False):
    status, health = request(endpoint, token, "GET", "/health")
    require(status == 200 and health.get("status") == "ok", "health failed")
    require(health.get("token") == token, "health token mismatch")
    require(health.get("backend") in {"gui", "idalib"}, "backend missing")
    for key in ("idb_path", "exe_path"):
        require(isinstance(health.get(key), str), f"health omitted {key}")
        require(not health[key] or os.path.isabs(health[key]), f"relative {key}")
    print(f"PASS health ({health['backend']})")

    status, result = request(
        endpoint,
        token,
        "POST",
        "/execute_python",
        {"code": "lambda database_path: {'database_path': database_path}"},
        compressed=True,
    )
    require(status == 200 and result.get("ok"), "execute_python failed")
    require(result["result"]["database_path"] == health["idb_path"], "wrong runtime")
    print("PASS compressed execute_python")

    pending = queue.Queue(maxsize=1)

    def slow_execute():
        pending.put(
            request(
                endpoint,
                token,
                "POST",
                "/execute_python",
                {
                    "code": (
                        "def run():\n    import time\n    time.sleep(0.5)\n    return 'done'"
                    )
                },
            )
        )

    thread = threading.Thread(target=slow_execute, daemon=True)
    thread.start()
    time.sleep(0.1)
    started = time.monotonic()
    require(
        request(endpoint, token, "GET", "/health")[0] == 200, "concurrent health failed"
    )
    require(time.monotonic() - started < 1.0, "health blocked on Python execution")
    thread.join(timeout=5)
    require(not thread.is_alive() and pending.get()[0] == 200, "slow execute failed")
    print("PASS health remains responsive during execute_python")

    status, analysis = request(endpoint, token, "GET", "/poll_autoanalysis")
    require(status == 200 and isinstance(analysis.get("complete"), bool), "poll failed")
    status, analysis = request(endpoint, token, "POST", "/wait_autoanalysis", {})
    require(status == 200 and analysis.get("complete") is True, "analysis wait failed")
    print("PASS autoanalysis lifecycle")

    if save:
        status, result = request(endpoint, token, "POST", "/save_database", {})
        require(status == 200 and result.get("result", {}).get("saved"), "save failed")
        print("PASS save_database")

    if health["backend"] == "gui":
        status, result = request(endpoint, token, "POST", "/close_database", {})
        require(status == 409, "GUI close_database did not fail")
        require(
            result.get("error", {}).get("code") == "gui_database_owned_by_user",
            "unexpected GUI close error",
        )
        print("PASS GUI close_database is forbidden")
    elif close:
        status, result = request(endpoint, token, "POST", "/close_database", {})
        require(
            status == 200 and result.get("result", {}).get("closed"), "close failed"
        )
        print("PASS idalib close_database")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("endpoint", help="http://127.0.0.1:<port>")
    parser.add_argument("--token")
    parser.add_argument("--registry-dir")
    parser.add_argument("--save", action="store_true")
    parser.add_argument("--close", action="store_true", help="Close an idalib worker")
    args = parser.parse_args()
    endpoint = args.endpoint.rstrip("/")
    parsed = urlsplit(endpoint)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
        raise SystemExit("endpoint must be http://127.0.0.1:<port>")
    token = args.token or discover_token(
        endpoint, args.registry_dir or get_registry_dir()
    )
    try:
        run(endpoint, token, save=args.save, close=args.close)
    except CheckFailed as exc:
        print(f"FAIL {exc}")
        return 1
    print("All live checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
