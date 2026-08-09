"""Benchmark a real IDA Code Mode endpoint through its public client and HTTP API.

The target is opened through DatabaseHandle so managed workers remain leased for
all measurements. Timings include response reads and JSON decoding, matching
what an interactive client observes.
"""

import argparse
import http.client
import importlib.metadata
import json
import math
import platform
import statistics
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ida_codemode.client import DatabaseHandle
from ida_codemode.registry import HOST

TRIVIAL_CODE = "result = 1"
IDA_CALL_CODE = """\
import ida_bytes
import ida_ida
_ea = ida_ida.inf_get_min_ea()
for _index in range(__IDA_CALL_ITERATIONS__):
    ida_bytes.get_flags(_ea)
{"iterations": __IDA_CALL_ITERATIONS__}
"""
LARGE_RESULT_CODE = """\
[
    {
        "ea": index,
        "name": f"sub_{index:x}",
        "text": "mov eax, ebx",
        "bytes": "4889d8",
        "flags": 3,
    }
    for index in range(__LARGE_RESULT_ITEMS__)
]
"""
ENVIRONMENT_CODE = """\
import sys
import idaapi
{
    "ida_version": idaapi.get_kernel_version(),
    "python_version": sys.version,
    "trace_installed": sys.gettrace() is not None,
}
"""


def percentile(sorted_samples: list[float], percentile_value: float) -> float:
    """Return a nearest-rank percentile from a non-empty sorted sample."""

    index = max(0, math.ceil(percentile_value * len(sorted_samples)) - 1)
    return sorted_samples[index]


def summarize(samples_ms: list[float]) -> dict[str, Any]:
    ordered = sorted(samples_ms)
    return {
        "iterations": len(ordered),
        "min_ms": ordered[0],
        "median_ms": statistics.median(ordered),
        "mean_ms": statistics.fmean(ordered),
        "p95_ms": percentile(ordered, 0.95),
        "p99_ms": percentile(ordered, 0.99),
        "max_ms": ordered[-1],
        "samples_ms": samples_ms,
    }


def measure(
    operation: Callable[[], Any],
    *,
    iterations: int,
    warmup: int,
) -> tuple[dict[str, Any], Any]:
    for _ in range(warmup):
        operation()
    samples_ms: list[float] = []
    result: Any = None
    for _ in range(iterations):
        started = time.perf_counter_ns()
        result = operation()
        samples_ms.append((time.perf_counter_ns() - started) / 1_000_000)
    return summarize(samples_ms), result


def measure_reported(
    operation: Callable[[], float],
    *,
    iterations: int,
    warmup: int,
) -> dict[str, Any]:
    """Summarize durations measured inside an operation with untimed cleanup."""

    for _ in range(warmup):
        operation()
    return summarize([operation() for _ in range(iterations)])


class Endpoint:
    def __init__(self, port: int, token: str, timeout: float) -> None:
        self.port = port
        self.token = token
        self.timeout = timeout

    def connection(self) -> http.client.HTTPConnection:
        return http.client.HTTPConnection(HOST, self.port, timeout=self.timeout)

    def request(
        self,
        connection: http.client.HTTPConnection,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> tuple[Any, int]:
        body = None
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}",
        }
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        try:
            response_body = response.read()
            status = response.status
        finally:
            response.close()
        try:
            decoded = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"{method} {path} returned invalid JSON") from exc
        if status != 200:
            raise RuntimeError(f"{method} {path} returned HTTP {status}: {decoded}")
        if method == "POST" and not decoded.get("ok"):
            raise RuntimeError(f"{method} {path} failed: {decoded}")
        return decoded, len(response_body)

    def fresh_request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
    ) -> tuple[Any, int]:
        connection = self.connection()
        try:
            return self.request(connection, method, path, payload)
        finally:
            connection.close()


def benchmark(args: argparse.Namespace) -> dict[str, Any]:
    opened_at = time.perf_counter_ns()
    handle = DatabaseHandle.open(
        str(args.target),
        spawn=not args.no_spawn,
        timeout=args.open_timeout,
        keepalive=args.keepalive,
    )
    handle_open_ms = (time.perf_counter_ns() - opened_at) / 1_000_000
    try:
        entry = handle.entry
        endpoint = Endpoint(entry.port, entry.token, args.request_timeout)
        health, _ = endpoint.fresh_request("GET", "/health")
        worker_environment = handle.execute_python(ENVIRONMENT_CODE)["result"]

        report: dict[str, Any] = {
            "schema": 1,
            "benchmark": "ida-codemode-performance",
            "created_at": time.time(),
            "client": {
                "ida_codemode_version": importlib.metadata.version("ida-codemode"),
                "python_version": sys.version,
                "platform": platform.platform(),
                "executable": sys.executable,
            },
            "instance": {
                "record_id": entry.record_id,
                "backend": entry.backend,
                "managed": entry.managed,
                "pid": entry.pid,
                "protocol_version": entry.version,
                "idb_path": entry.idb_path,
                "exe_path": entry.exe_path,
                **worker_environment,
            },
            "parameters": {
                "iterations": args.iterations,
                "warmup": args.warmup,
                "workload_iterations": args.workload_iterations,
                "ida_call_iterations": args.ida_call_iterations,
                "large_result_items": args.large_result_items,
            },
            "one_time": {
                "handle_open_ms": handle_open_ms,
                "health": health,
            },
            "metrics": {},
        }
        metrics: dict[str, Any] = report["metrics"]

        def fresh_tcp_connection() -> float:
            connection = endpoint.connection()
            try:
                started = time.perf_counter_ns()
                connection.connect()
                elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
                # Complete one request outside the measured interval. Closing
                # immediately after connect can outrun accept(), fill the small
                # listener backlog in older servers, and benchmark Linux's
                # one-second SYN retry rather than ordinary connection setup.
                endpoint.request(connection, "GET", "/health")
                return elapsed_ms
            finally:
                connection.close()

        metrics["tcp_connect_fresh"] = measure_reported(
            fresh_tcp_connection,
            iterations=args.iterations,
            warmup=args.warmup,
        )
        metrics["health_fresh_connection"], _ = measure(
            lambda: endpoint.fresh_request("GET", "/health"),
            iterations=args.iterations,
            warmup=args.warmup,
        )

        health_connection = endpoint.connection()
        try:
            metrics["health_reused_connection"], _ = measure(
                lambda: endpoint.request(health_connection, "GET", "/health"),
                iterations=args.iterations,
                warmup=args.warmup,
            )
        finally:
            health_connection.close()

        trivial_payload = {"code": TRIVIAL_CODE, "timeout": args.execution_timeout}
        metrics["execute_trivial_fresh_connection"], _ = measure(
            lambda: endpoint.fresh_request(
                "POST",
                "/execute_python",
                trivial_payload,
            ),
            iterations=args.iterations,
            warmup=args.warmup,
        )

        execute_connection = endpoint.connection()
        try:
            metrics["execute_trivial_reused_connection"], _ = measure(
                lambda: endpoint.request(
                    execute_connection,
                    "POST",
                    "/execute_python",
                    trivial_payload,
                ),
                iterations=args.iterations,
                warmup=args.warmup,
            )
        finally:
            execute_connection.close()

        metrics["execute_trivial_database_handle"], _ = measure(
            lambda: handle.execute_python(
                TRIVIAL_CODE,
                timeout=args.execution_timeout,
            ),
            iterations=args.iterations,
            warmup=args.warmup,
        )

        ida_call_code = IDA_CALL_CODE.replace(
            "__IDA_CALL_ITERATIONS__",
            str(args.ida_call_iterations),
        )
        ida_connection = endpoint.connection()
        try:
            ida_metric, ida_response = measure(
                lambda: endpoint.request(
                    ida_connection,
                    "POST",
                    "/execute_python",
                    {"code": ida_call_code, "timeout": args.execution_timeout},
                ),
                iterations=args.workload_iterations,
                warmup=min(args.warmup, 2),
            )
        finally:
            ida_connection.close()
        _ida_payload, ida_response_bytes = ida_response
        ida_metric["response_bytes"] = ida_response_bytes
        ida_metric["workload"] = {
            "operation": "ida_bytes.get_flags",
            "calls_per_iteration": args.ida_call_iterations,
        }
        metrics["execute_ida_get_flags_loop_reused_connection"] = ida_metric

        large_result_code = LARGE_RESULT_CODE.replace(
            "__LARGE_RESULT_ITEMS__",
            str(args.large_result_items),
        )
        large_connection = endpoint.connection()
        try:
            large_metric, large_response = measure(
                lambda: endpoint.request(
                    large_connection,
                    "POST",
                    "/execute_python",
                    {
                        "code": large_result_code,
                        "timeout": args.execution_timeout,
                    },
                ),
                iterations=args.workload_iterations,
                warmup=min(args.warmup, 2),
            )
        finally:
            large_connection.close()
        _large_payload, large_response_bytes = large_response
        large_metric["response_bytes"] = large_response_bytes
        large_metric["workload"] = {
            "result_items": args.large_result_items,
        }
        metrics["execute_large_json_reused_connection"] = large_metric

        return report
    finally:
        handle.close()


def metric_label(name: str, metric: dict[str, Any]) -> str:
    labels = {
        "tcp_connect_fresh": "TCP connect (fresh connection)",
        "health_fresh_connection": "GET /health (fresh connection)",
        "health_reused_connection": "GET /health (reused connection)",
        "execute_trivial_fresh_connection": ('execute "result = 1" (fresh connection)'),
        "execute_trivial_reused_connection": (
            'execute "result = 1" (reused connection)'
        ),
        "execute_trivial_database_handle": (
            'DatabaseHandle.execute_python("result = 1")'
        ),
    }
    if name == "execute_ida_get_flags_loop_reused_connection":
        calls = metric["workload"]["calls_per_iteration"]
        return f"{calls:,}-call ida_bytes.get_flags loop"
    if name == "execute_large_json_reused_connection":
        items = metric["workload"]["result_items"]
        response_bytes = metric["response_bytes"]
        return f"{items:,}-item JSON result ({response_bytes:,} byte response)"
    return labels.get(name, name)


def print_human(report: dict[str, Any]) -> None:
    instance = report["instance"]
    client = report["client"]
    print("IDA Code Mode performance benchmark")
    print(f"  ida-codemode: {client['ida_codemode_version']}")
    print(f"  client:       {client['platform']}")
    print(
        f"  worker:       IDA {instance['ida_version']}, "
        f"Python {instance['python_version'].split()[0]}, "
        f"{instance['backend']} pid {instance['pid']}"
    )
    parameters = report["parameters"]
    print(f"  trace hook:   {instance['trace_installed']}")
    print(f"  handle open (one time): {report['one_time']['handle_open_ms']:.3f} ms")
    print(
        f"  sampling:     {parameters['warmup']} warmups, then "
        f"{parameters['iterations']} request samples "
        f"({parameters['workload_iterations']} workload samples)"
    )
    print()
    print("End-to-end latency; each sample is one complete operation/request")
    print(
        f"{'operation':70} {'samples':>7} {'median':>12} {'p95':>12} "
        f"{'mean':>12} {'min':>12} {'max':>12}"
    )
    print("-" * 150)
    for name, metric in report["metrics"].items():
        print(
            f"{metric_label(name, metric):70} {metric['iterations']:7d} "
            f"{metric['median_ms']:9.3f} ms {metric['p95_ms']:9.3f} ms "
            f"{metric['mean_ms']:9.3f} ms {metric['min_ms']:9.3f} ms "
            f"{metric['max_ms']:9.3f} ms"
        )


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must not be negative")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path, help="executable or existing IDB")
    parser.add_argument("--iterations", type=positive_int, default=200)
    parser.add_argument("--warmup", type=non_negative_int, default=20)
    parser.add_argument("--workload-iterations", type=positive_int, default=10)
    parser.add_argument("--ida-call-iterations", type=positive_int, default=20_000)
    parser.add_argument("--large-result-items", type=positive_int, default=500)
    parser.add_argument("--execution-timeout", type=float, default=30.0)
    parser.add_argument("--request-timeout", type=float, default=60.0)
    parser.add_argument("--open-timeout", type=float, default=120.0)
    parser.add_argument("--keepalive", type=float, default=0.0)
    parser.add_argument(
        "--no-spawn",
        action="store_true",
        help="require an existing GUI or idalib instance",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the complete machine-readable report instead of a table",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="also write the complete machine-readable report to this path",
    )
    args = parser.parse_args()

    for name in ("execution_timeout", "request_timeout", "open_timeout"):
        value = getattr(args, name)
        if not math.isfinite(value) or value <= 0:
            parser.error(f"--{name.replace('_', '-')} must be positive and finite")
    if not math.isfinite(args.keepalive) or args.keepalive < 0:
        parser.error("--keepalive must be non-negative and finite")

    report = benchmark(args)
    encoded = json.dumps(report, indent=2, sort_keys=True)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
    if args.json:
        print(encoded)
    else:
        print_human(report)
        if args.output is not None:
            print(f"\nWrote JSON report to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
