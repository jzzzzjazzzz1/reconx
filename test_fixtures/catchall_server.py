"""
Simulates a 'soft 404' / SPA catch-all host: returns HTTP 200 with the
SAME body for every single path, including /.git/HEAD and /admin.
This is the classic false-positive trap for recon tools. A naive tool
that flags "200 on /admin" or "200 on /.git/HEAD" as a finding would
wrongly flag this host. ReconX's baseline-comparison logic should NOT
flag it.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

PAGE = b"<html><body><h1>My Single Page App</h1><div id='root'></div></body></html>"


class CatchAllHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx")
        self.end_headers()
        self.wfile.write(PAGE)

    def log_message(self, format, *args):
        pass  # keep test output quiet


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    HTTPServer(("127.0.0.1", port), CatchAllHandler).serve_forever()
