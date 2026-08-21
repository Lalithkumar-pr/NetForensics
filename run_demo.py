"""
Standalone Python Standard-Library Server Runner for NetForensics (Final Phase Demo).
Serves the Frontend Investigation Dashboard and API endpoints with zero third-party dependencies.

Usage:
    python run_demo.py
"""

import http.server
import json
import os
import socketserver
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from backend.app.api.router import get_available_scenarios, run_investigation

PORT = 8000


class NetForensicsHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """
    Custom HTTP Request Handler for NetForensics dashboard and API.
    """

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == "/api/scenarios":
            scenarios = get_available_scenarios()
            self._send_json({"status": "success", "scenarios": scenarios})
            return

        if path in ("/", "/index.html"):
            self._serve_file("frontend/index.html", "text/html")
            return

        if path.startswith("/static/"):
            rel_path = path.replace("/static/", "frontend/")
            mime_type = "text/css" if rel_path.endswith(".css") else ("application/javascript" if rel_path.endswith(".js") else "text/html")
            self._serve_file(rel_path, mime_type)
            return

        # Fallback file serving from workspace root or frontend
        if os.path.exists(path.lstrip("/")):
            super().do_GET()
        else:
            self._serve_file("frontend/index.html", "text/html")

    def do_POST(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == "/api/investigate":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length).decode("utf-8")
            try:
                data = json.loads(post_data) if post_data else {}
                scenario_id = data.get("scenario_id", "")
            except Exception:
                scenario_id = ""

            if not scenario_id:
                self._send_json({"status": "error", "error": "scenario_id is required"}, status=400)
                return

            result = run_investigation(scenario_id)
            status_code = 200 if result.get("status") == "success" else 404
            self._send_json(result, status=status_code)
            return

        self._send_json({"status": "error", "error": "Endpoint not found"}, status=404)

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, file_path: str, mime_type: str):
        path = Path(file_path)
        if not path.exists():
            self.send_error(404, "File Not Found")
            return

        content = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{mime_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def main():
    """Starts the NetForensics HTTP server on port 8000."""
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), NetForensicsHTTPRequestHandler) as httpd:
        print("==================================================================")
        print(f" NetForensics Investigation Dashboard Running on http://localhost:{PORT}")
        print(" Evidence-Driven • Deterministic • Auditable Incident Reconstruction")
        print(" Press Ctrl+C to stop the server.")
        print("==================================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down NetForensics server.")


if __name__ == "__main__":
    main()
