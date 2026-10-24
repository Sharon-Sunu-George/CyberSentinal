"""
CyberSentinal Live Demo Target Server
Provides a controlled local HTTP server with toggleable security headers and security.txt.
Used for local demonstration of the Attacker Agent -> Defender Agent -> Fix Verification loop.

Usage:
    python tests/demo_target.py [--port 8888]
"""

import http.server
import socketserver
import argparse
import sys

# Global toggle state
CONFIG = {
    "enable_csp": False,
    "enable_hsts": False,
    "disclose_server": True,
    "has_security_txt": False,
}

class DemoTargetHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Keep terminal output clean
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))

    def do_GET(self):
        # Endpoints to toggle configuration during demo
        if self.path == "/toggle/csp":
            CONFIG["enable_csp"] = not CONFIG["enable_csp"]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"CSP is now {'ENABLED' if CONFIG['enable_csp'] else 'DISABLED'}\n".encode())
            return

        if self.path == "/toggle/security-txt":
            CONFIG["has_security_txt"] = not CONFIG["has_security_txt"]
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"security.txt is now {'ENABLED' if CONFIG['has_security_txt'] else 'DISABLED'}\n".encode())
            return

        if self.path == "/.well-known/security.txt":
            if CONFIG["has_security_txt"]:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Contact: mailto:security@cybersentinal.local\nExpires: 2028-12-31T23:59:59.000Z\n")
            else:
                self.send_response(404)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>404 Not Found</body></html>")
            return

        # Main application endpoint
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")

        if CONFIG["disclose_server"]:
            self.send_header("Server", "Apache/2.4.52 (Ubuntu)")

        if CONFIG["enable_csp"]:
            self.send_header("Content-Security-Policy", "default-src 'self'")

        self.end_headers()
        html = f"""<!DOCTYPE html>
<html>
<head><title>CyberSentinal Demo Target</title></head>
<body>
    <h1>Controlled Demo Target Application</h1>
    <p>Current Status: CSP is <strong>{'ENABLED' if CONFIG['enable_csp'] else 'DISABLED'}</strong></p>
    <p>Toggle via GET <code>/toggle/csp</code> or <code>/toggle/security-txt</code></p>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))

def main():
    parser = argparse.ArgumentParser(description="Run CyberSentinal local test target")
    parser.add_argument("--port", type=int, default=8888, help="Port to bind (default: 8888)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    args = parser.parse_args()

    server_address = (args.host, args.port)
    with socketserver.TCPServer(server_address, DemoTargetHandler) as httpd:
        print(f"[*] CyberSentinal Demo Target listening at http://{args.host}:{args.port}")
        print(f"[*] Toggle CSP: http://{args.host}:{args.port}/toggle/csp")
        print(f"[*] Toggle security.txt: http://{args.host}:{args.port}/toggle/security-txt")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Shutting down demo server.")

if __name__ == "__main__":
    main()
