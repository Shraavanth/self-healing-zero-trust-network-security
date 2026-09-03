import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

from logger import log_event


HONEYPOT_HOST = "127.0.0.1"
HONEYPOT_PORT = 8080

honeypot_server = None
honeypot_thread = None
honeypot_running = False


class HoneypotHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        """Keep default HTTP server output quiet."""
        pass

    def do_GET(self):
        source = self.client_address[0]

        log_event(
            "HONEYPOT_ACTIVITY",
            {
                "source_ip": source,
                "method": "GET",
                "path": self.path
            }
        )

        print("\n[HONEYPOT ACTIVITY]")
        print(f"Time: {datetime.now().isoformat()}")
        print(f"Source IP: {source}")
        print(f"Requested path: {self.path}")

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        response = """
        <html>
        <head>
            <title>Network Service</title>
        </head>
        <body>
            <h1>Network Service</h1>
            <p>Service is currently available.</p>
        </body>
        </html>
        """

        self.wfile.write(response.encode())

    def do_POST(self):
        source = self.client_address[0]

        content_length = int(
            self.headers.get("Content-Length", 0)
        )

        body = self.rfile.read(content_length)

        log_event(
            "HONEYPOT_ACTIVITY",
            {
                "source_ip": source,
                "method": "POST",
                "path": self.path,
                "request_size": len(body)
            }
        )

        print("\n[HONEYPOT POST ACTIVITY]")
        print(f"Time: {datetime.now().isoformat()}")
        print(f"Source IP: {source}")
        print(f"Requested path: {self.path}")
        print(f"Request size: {len(body)} bytes")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        self.wfile.write(
            b"Request received by monitored service."
        )


def start_honeypot():
    """Start the honeypot service."""

    global honeypot_server
    global honeypot_thread
    global honeypot_running

    if honeypot_running:
        print("[HONEYPOT] Already running.")
        return False

    try:
        honeypot_server = HTTPServer(
            (HONEYPOT_HOST, HONEYPOT_PORT),
            HoneypotHandler
        )

        honeypot_thread = threading.Thread(
            target=honeypot_server.serve_forever,
            daemon=True
        )

        honeypot_thread.start()
        honeypot_running = True

        log_event(
            "HONEYPOT_STARTED",
            {
                "host": HONEYPOT_HOST,
                "port": HONEYPOT_PORT
            }
        )

        print(
            f"[HONEYPOT] Started on "
            f"http://{HONEYPOT_HOST}:{HONEYPOT_PORT}"
        )

        return True

    except OSError as error:
        print(f"[HONEYPOT] Failed to start: {error}")
        return False


def stop_honeypot():
    """Stop the honeypot service."""

    global honeypot_server
    global honeypot_thread
    global honeypot_running

    if not honeypot_running:
        print("[HONEYPOT] Not currently running.")
        return False

    honeypot_server.shutdown()
    honeypot_server.server_close()

    log_event(
        "HONEYPOT_STOPPED",
        {
            "host": HONEYPOT_HOST,
            "port": HONEYPOT_PORT
        }
    )

    honeypot_server = None
    honeypot_thread = None
    honeypot_running = False

    print("[HONEYPOT] Stopped.")

    return True


def is_honeypot_running():
    """Return the current honeypot status."""

    return honeypot_running