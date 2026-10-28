#!/usr/bin/env python3
"""Minimal loopback HTTP server for the Titan scroll-stability browser harness.

Serves exactly two things, read-only:
  /                -> the harness page (--page)
  /web/<relative>  -> the real web asset tree (--web-root), including titan.js
  /__meta.json     -> {"webRoot": <absolute web root>, "page": <harness page>}

No external dependencies (Python standard library only), binds 127.0.0.1 only,
prints "PORT=<n>" on stdout as soon as it is listening so the Node runner can
read the ephemeral port and start headless Chrome.

Usage:
  python titan_scroll_server.py --web-root <dir> --page <file> [--port 0]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

CONTENT_TYPES = {
    '.css': 'text/css; charset=utf-8',
    '.html': 'text/html; charset=utf-8',
    '.ico': 'image/x-icon',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.map': 'application/json; charset=utf-8',
    '.mjs': 'text/javascript; charset=utf-8',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
}


class HarnessHandler(BaseHTTPRequestHandler):
    server_version = 'VgtTitanScrollHarness/1.0'
    protocol_version = 'HTTP/1.1'
    web_root = ''
    page_path = ''

    # The harness is intentionally quiet: Chrome's own stderr is already logged
    # by the runner and request lines would only add noise.
    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        pass

    def _send_bytes(self, body, content_type):
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _send_status(self, status):
        self.send_response(status)
        self.send_header('Content-Length', '0')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()

    def _safe_web_target(self, relative):
        root = self.web_root
        parts = [part for part in relative.split('/') if part not in ('', '.', '..')]
        target = os.path.realpath(os.path.join(root, *parts))
        if target != root and not target.startswith(root + os.sep):
            return None
        return target

    def do_GET(self):  # noqa: N802 - stdlib signature
        path = unquote(urlsplit(self.path).path)
        if path in ('/', '/index.html'):
            return self._send_file(self.page_path, 'text/html; charset=utf-8')
        if path == '/__meta.json':
            body = json.dumps({'webRoot': self.web_root, 'page': self.page_path}).encode('utf-8')
            return self._send_bytes(body, 'application/json; charset=utf-8')
        if path == '/favicon.ico':
            return self._send_status(204)
        if path.startswith('/web/'):
            target = self._safe_web_target(path[len('/web/'):])
            if target is None:
                return self._send_status(403)
            if not os.path.isfile(target):
                return self._send_status(404)
            extension = os.path.splitext(target)[1].lower()
            return self._send_file(target, CONTENT_TYPES.get(extension, 'application/octet-stream'))
        return self._send_status(404)

    def _send_file(self, target, content_type):
        try:
            with open(target, 'rb') as handle:
                body = handle.read()
        except OSError:
            return self._send_status(404)
        self._send_bytes(body, content_type)


def main():
    parser = argparse.ArgumentParser(description='Serve the Titan scroll-stability harness.')
    parser.add_argument('--web-root', required=True, help='Real web asset directory served under /web/')
    parser.add_argument('--page', required=True, help='Harness HTML page served at /')
    parser.add_argument('--port', type=int, default=0, help='Listening port (0 = ephemeral)')
    args = parser.parse_args()

    web_root = os.path.realpath(args.web_root)
    page_path = os.path.realpath(args.page)
    if not os.path.isdir(web_root):
        print('ERROR web-root is not a directory: ' + web_root, file=sys.stderr, flush=True)
        return 2
    if not os.path.isfile(page_path):
        print('ERROR harness page not found: ' + page_path, file=sys.stderr, flush=True)
        return 2

    HarnessHandler.web_root = web_root
    HarnessHandler.page_path = page_path
    server = ThreadingHTTPServer(('127.0.0.1', args.port), HarnessHandler)
    print('PORT=' + str(server.server_address[1]), flush=True)
    try:
        server.serve_forever(poll_interval=0.05)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
