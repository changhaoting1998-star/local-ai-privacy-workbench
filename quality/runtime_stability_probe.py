"""Repeatable, read-only smoke probe for the running personal loopback service."""
from __future__ import annotations

import hashlib
import json
import time
import urllib.request
from pathlib import Path


BASE = "http://127.0.0.1:8910"
ROUNDS = 30
OUT = Path(__file__).resolve().parent / "runtime-stability-results.json"


def open_local(path: str):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(BASE + path, headers={"Host": "127.0.0.1:8910"})
    return opener.open(request, timeout=2)


def main() -> int:
    latencies_ms: list[float] = []
    root_hashes: set[str] = set()
    failures: list[dict[str, object]] = []
    for index in range(ROUNDS):
        started = time.perf_counter()
        try:
            with open_local("/api/health") as response:
                health = json.load(response)
                assert response.status == 200
                assert health["status"] == "ok"
                assert health["mode"] == "LOCAL_MOCK_ONLY"
                assert health["deployment_mode"] == "loopback"
                assert response.headers["Cache-Control"] == "no-store"
                assert "default-src 'self'" in response.headers["Content-Security-Policy"]
            with open_local("/") as response:
                body = response.read()
                assert response.status == 200
                assert "text/html" in response.headers["Content-Type"]
                assert b"<div id=\"root\"></div>" in body
                root_hashes.add(hashlib.sha256(body).hexdigest())
            latencies_ms.append(round((time.perf_counter() - started) * 1000, 2))
        except Exception as exc:
            failures.append({"round": index + 1, "error": type(exc).__name__})

    result = {
        "base": BASE,
        "rounds": ROUNDS,
        "passed": ROUNDS - len(failures),
        "failed": len(failures),
        "stable_root_build": len(root_hashes) == 1,
        "min_ms": min(latencies_ms) if latencies_ms else None,
        "max_ms": max(latencies_ms) if latencies_ms else None,
        "average_ms": round(sum(latencies_ms) / len(latencies_ms), 2) if latencies_ms else None,
        "failures": failures,
    }
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return 0 if not failures and len(root_hashes) == 1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
