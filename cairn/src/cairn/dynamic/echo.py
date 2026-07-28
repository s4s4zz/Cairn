"""The out-of-band echo service (§9.4).

SSRF, command execution and XXE are confirmed by making the application reach
*this* service rather than by interpreting whatever the application chose to
return. A request carrying a nonce the probe planted is proof the payload was
executed; no response-body heuristic gives the same certainty.

The service lives on ``validation-net-<run-id>``, which is ``internal: true``,
so it is reachable only from inside the sandbox group and disappears with it.

It records nonces and nothing else. A request body is read up to a small cap
and then discarded: this is a tripwire, not a proxy, and storing what an
application sent it would make it one more place repository data accumulates.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import re
import sys
import threading

ECHO_PORT = 8081
NONCE_PATTERN = re.compile(r"cairn-[0-9a-f]{32}")
MAX_READ_BYTES = 8192
MAX_NONCES = 4096

_lock = threading.Lock()
_observed: set[str] = set()


def observed() -> set[str]:
    with _lock:
        return set(_observed)


def _record(*sources: str) -> None:
    with _lock:
        if len(_observed) >= MAX_NONCES:
            return
        for source in sources:
            for match in NONCE_PATTERN.findall(source or ""):
                _observed.add(match)


class _Handler(BaseHTTPRequestHandler):
    # The default logs one line per request to stderr, which in a container is
    # captured output nobody reads and one more place request data lands.
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        del format, args

    def _observe(self) -> None:
        body = ""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            length = 0
        if 0 < length <= MAX_READ_BYTES:
            body = self.rfile.read(length).decode("utf-8", errors="replace")
        _record(self.path, body, str(self.headers.get("User-Agent") or ""))

    def _respond(self, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path.startswith("/__cairn/observed"):
            # The probe runner asks what has been seen. Reachable only from the
            # isolated network, and it returns nonces the platform generated.
            self._respond({"nonces": sorted(observed())})
            return
        self._observe()
        self._respond({"ok": True})

    def do_POST(self) -> None:  # noqa: N802
        self._observe()
        self._respond({"ok": True})

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_GET
    do_HEAD = do_GET


def serve(port: int = ECHO_PORT) -> None:  # pragma: no cover - container entry
    server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:  # pragma: no cover
    del argv
    try:
        serve()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
