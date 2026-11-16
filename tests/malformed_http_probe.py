"""
Isolated malformed-HTTP-response probe for SAST-014 (CVE-2026-69244 class).

Run as a *separate process* by tests/test_dependency_lock.py so that a memory
safety fault in aiohttp's C response parser (segfault / abort) shows up as a
non-zero exit status instead of taking the pytest process down with it.

A raw asyncio TCP server on 127.0.0.1 (ephemeral port, this process only)
answers every connection with one canned, deliberately malformed response.
Each case is fetched twice: once with a bare aiohttp.ClientSession (the
parser as shipped) and once through src.safehttp.SafeHttpClient (the path
the url/pubcom plugins use for user-supplied URLs). Results are printed as a
single JSON document on stdout. No external network, DNS, IRC or bot.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

# Allow "python tests/malformed_http_probe.py" from the repo root.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import aiohttp  # noqa: E402
import aiohttp.http_parser as http_parser  # noqa: E402

from src.safehttp import FetchError, SafeFetchPolicy, SafeHttpClient  # noqa: E402

LOOPBACK = "127.0.0.1"
OK_BODY = b"<html><head><title>ok</title></head></html>"

# name -> (raw bytes sent by the server before closing, expectation)
#   "error": the client MUST raise a handled exception (never return data)
#   "ok":    a well-formed control response that MUST succeed
CASES: dict[str, tuple[bytes, str]] = {
    "control_well_formed": (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
        + str(len(OK_BODY)).encode() + b"\r\nConnection: close\r\n\r\n" + OK_BODY,
        "ok",
    ),
    "non_numeric_status": (b"HTTP/1.1 abc OK\r\nContent-Length: 0\r\n\r\n", "error"),
    "truncated_status_line": (b"HTTP/1.1 20", "error"),
    "not_http_at_all": (b"\x16\x03\x01\x02\x00garbage\x00\xff\xfe\r\n\r\n", "error"),
    "header_without_colon": (
        b"HTTP/1.1 200 OK\r\nBadHeaderLine\r\nContent-Length: 2\r\n\r\nok", "error"),
    "nul_in_header_value": (
        b"HTTP/1.1 200 OK\r\nX-A: a\x00b\r\nContent-Length: 2\r\n\r\nok", "error"),
    "nul_in_header_name": (
        b"HTTP/1.1 200 OK\r\nX\x00A: v\r\nContent-Length: 2\r\n\r\nok", "error"),
    "invalid_chunk_size": (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nabc\r\n0\r\n\r\n",
        "error"),
    "chunk_size_overflow": (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"ffffffffffffffffffffffffffffffff\r\nabc\r\n0\r\n\r\n", "error"),
    "negative_content_length": (
        b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nok", "error"),
    "non_numeric_content_length": (
        b"HTTP/1.1 200 OK\r\nContent-Length: 1x\r\n\r\nok", "error"),
    "duplicate_conflicting_content_length": (
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 9\r\n\r\nok", "error"),
    "truncated_body": (
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort", "error"),
    "truncated_chunked_body": (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nabc", "error"),
    "truncated_headers": (b"HTTP/1.1 200 OK\r\nContent-Type: text/ht", "error"),
    "oversized_header_line": (
        b"HTTP/1.1 200 OK\r\nX-Big: " + b"A" * 200_000 + b"\r\nContent-Length: 2\r\n\r\nok",
        "error"),
    "oversized_status_reason": (
        b"HTTP/1.1 200 " + b"R" * 200_000 + b"\r\nContent-Length: 2\r\n\r\nok", "error"),
    "too_many_headers": (
        b"HTTP/1.1 200 OK\r\n"
        + b"".join(b"X-%d: v\r\n" % i for i in range(5000))
        + b"Content-Length: 2\r\n\r\nok", "error"),
    "control_chars_in_status_line": (
        b"HTTP/1.1 2\x0100 OK\r\nContent-Length: 0\r\n\r\n", "error"),
    "bad_http_version": (b"HTTP/9.Z 200 OK\r\nContent-Length: 2\r\n\r\nok", "error"),
    "empty_reply": (b"", "error"),
}


async def _serve(writer_payloads: dict[str, bytes]):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            path = head.split(b" ", 2)[1].decode("ascii", "replace").lstrip("/")
            payload = writer_payloads.get(path, b"HTTP/1.1 404 Not Found\r\n"
                                                b"Content-Length: 0\r\n\r\n")
            writer.write(payload)
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    return await asyncio.start_server(handle, LOOPBACK, 0)


async def _bare(session: aiohttp.ClientSession, url: str) -> dict:
    try:
        async with session.get(url, allow_redirects=False) as resp:
            body = await resp.read()
            return {"outcome": "ok", "status": resp.status, "len": len(body)}
    except aiohttp.ClientError as exc:
        return {"outcome": "error", "exc": type(exc).__name__}
    except (asyncio.TimeoutError, TimeoutError) as exc:
        return {"outcome": "error", "exc": type(exc).__name__}
    except Exception as exc:  # unexpected exception type: report, don't crash
        return {"outcome": "unexpected", "exc": f"{type(exc).__name__}: {exc}"[:200]}


async def _safe(client: SafeHttpClient, url: str) -> dict:
    try:
        res = await client.fetch(url)
        return {"outcome": "ok", "status": res.status, "len": len(res.body)}
    except FetchError as exc:
        return {"outcome": "error", "exc": type(exc).__name__}
    except Exception as exc:
        return {"outcome": "unexpected", "exc": f"{type(exc).__name__}: {exc}"[:200]}


async def main() -> dict:
    server = await _serve({name: raw for name, (raw, _) in CASES.items()})
    port = server.sockets[0].getsockname()[1]
    policy = SafeFetchPolicy(ports=frozenset({port}), allow_networks=("127.0.0.1/32",),
                             total_timeout=5.0, connect_timeout=2.0)
    safe = SafeHttpClient(policy)
    timeout = aiohttp.ClientTimeout(total=5, connect=2)
    results: dict[str, dict] = {}
    try:
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
            # Run every case, then the control again, to prove the process
            # (and the parser) is still healthy after the malformed inputs.
            for name in list(CASES) + ["control_well_formed"]:
                url = f"http://{LOOPBACK}:{port}/{name}"
                key = name if name not in results else name + "_after"
                results[key] = {
                    "expect": CASES[name][1],
                    "bare": await _bare(session, url),
                    "safe": await _safe(safe, url),
                }
    finally:
        await safe.close()
        server.close()
        await server.wait_closed()
    return results


if __name__ == "__main__":
    report = {
        "aiohttp": aiohttp.__version__,
        "c_parser": http_parser.HttpResponseParser
        is getattr(http_parser, "HttpResponseParserC", None),
        "results": asyncio.run(main()),
    }
    print(json.dumps(report, sort_keys=True))
