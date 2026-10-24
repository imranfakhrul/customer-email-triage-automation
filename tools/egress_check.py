"""Run any Python entrypoint with outbound HTTP blocked, print what would be sent,
and flag forbidden strings.

Usage:
  python tools/egress_check.py --forbid "John Smith" --forbid 4111 -- main.py --input x.json
"""
import os, sys, runpy

args = sys.argv[1:]
if "--" not in args:
    sys.exit("usage: egress_check.py [--forbid TEXT]... -- script.py [script args]")
i = args.index("--")
opts, target = args[:i], args[i + 1:]
forbid = [opts[j + 1] for j, a in enumerate(opts) if a == "--forbid" and j + 1 < len(opts)]

sys.path.insert(0, os.getcwd())
try:
    import dotenv
    dotenv.load_dotenv = lambda *a, **k: False   # keep real keys from .env out of the check
except ImportError:
    pass

captured = []
import requests

def blocked_send(self, request, **kw):
    captured.append(("requests", str(request.url), request.body))
    raise requests.exceptions.ConnectionError("blocked by egress check")
requests.adapters.HTTPAdapter.send = blocked_send

try:
    import httpx
    def blocked_httpx(self, request, *a, **kw):
        try:
            body = request.content
        except Exception:
            body = b""
        captured.append(("httpx", str(request.url), body))
        raise httpx.ConnectError("blocked by egress check")
    httpx.HTTPTransport.handle_request = blocked_httpx
except ImportError:
    pass

sys.argv = target
try:
    runpy.run_path(target[0], run_name="__main__")
except SystemExit:
    pass

print("\n\n===== EGRESS CHECK: what would have been sent outside =====")
leaks = 0
if not captured:
    print("NOTHING WAS SENT OUTSIDE")
for kind, url, body in captured:
    text = body.decode("utf-8", "ignore") if isinstance(body, bytes) else str(body)
    print("\n[" + kind + "] " + url + "\n" + text + "\n")
    for f in forbid:
        bad = f in text
        leaks += bad
        print(("LEAK   " if bad else "clean  ") + f)
print("\nRESULT: " + ("LEAKS FOUND" if leaks else "no forbidden text left the machine"))
sys.exit(1 if leaks else 0)
