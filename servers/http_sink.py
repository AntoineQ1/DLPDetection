import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class SinkHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="ignore")
        print(f"[ATTACKER-C2] Received POST from {self.client_address[0]}: {body}")
        sys.stdout.flush()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK\n")

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 80), SinkHandler)
    print("[ATTACKER-C2] HTTP sink listening on port 80...")
    sys.stdout.flush()
    server.serve_forever()