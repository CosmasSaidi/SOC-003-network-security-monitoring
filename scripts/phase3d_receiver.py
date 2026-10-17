#!/usr/bin/env python3
"""Bounded one-shot HTTP receiver: accepts PUT/POST of lab capture artifacts from
WS001 (192.168.56.102) to the Kali sensor (192.168.56.1) over the existing
host-only link. Writes into the given directory; reframes filenames."""
import hashlib, http.server, os, sys, threading

ROOT = sys.argv[1]; PORT = int(sys.argv[2]); ALLOW = sys.argv[3] if len(sys.argv) > 3 else None

class H(http.server.BaseHTTPRequestHandler):
    server_version = "soc003-p3d/1.0"
    def _name(self):
        n = os.path.basename(self.path.lstrip("/")) or "upload.bin"
        return n.replace(".", "_", 0) if False else n
    def _recv(self):
        if ALLOW and self.client_address[0] != ALLOW:
            self.send_response(403); self.end_headers(); self.wfile.write(b"forbidden"); return
        n = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(n)
        name = self._name()
        dest = os.path.join(ROOT, name)
        with open(dest, "wb") as f: f.write(data)
        h = hashlib.sha256(data).hexdigest()
        print(f"RECV {name} {len(data)} bytes sha256={h} from {self.client_address[0]}", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(f"OK {len(data)} {h}\n".encode())
    do_PUT = _recv
    do_POST = _recv
    def log_message(self, *a): pass

srv = http.server.HTTPServer(("0.0.0.0", PORT), H)
print(f"listening on 0.0.0.0:{PORT} -> {ROOT}", flush=True)
srv.timeout = 300
t = threading.Timer(420, srv.shutdown); t.daemon = True; t.start()
srv.serve_forever()
