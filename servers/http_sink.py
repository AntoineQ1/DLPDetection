from http.server import BaseHTTPRequestHandler, HTTPServer

from ui.display import (
    print_hint,
    print_status,
    print_success,
    render_debug_flow,
    render_payload_telemetry,
)


class SinkHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(length)

        src_ip = self.client_address[0]
        dst_ip = self.headers.get("Host", "0.0.0.0")

        render_debug_flow("HTTP", src_ip, dst_ip)
        panel_title = f"Intercepted HTTP POST [from {src_ip}]"
        render_payload_telemetry(payload, panel_title=panel_title)
        print_success(f"Extracted {len(payload)} bytes from {src_ip}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK\n")


def main():
    server = HTTPServer(("0.0.0.0", 80), SinkHandler)
    print_status("Starting HTTP listener...")
    print_hint("Listening on port 80 for POST requests...")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print_status("Stopping listener...")


if __name__ == "__main__":
    main()