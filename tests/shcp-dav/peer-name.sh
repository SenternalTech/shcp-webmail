#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# shcp_dav pins shcpd's loopback certificate by its own name while the Host header
# stays the panel's (shcp-master#4369, SC-904/SC-737). A local TLS fixture on
# 127.0.0.1 serves a certificate named only for loopback and echoes the Host it got.
# Guards: the pinned peer name verifies; the origin's host alone does not; another
# self-signed certificate for the same names is refused; a peer name
# without a cafile is refused at construction; a php.ini openssl.capath holding the
# other certificate adds no trust beside the pinned file.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"; pid=""
trap '[[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null; rm -rf -- "${work}"' EXIT
san='subjectAltName=IP:127.0.0.1,IP:::1,DNS:shcpd.loopback.invalid'
for n in loop other; do
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=$n" \
        -addext "${san}" -addext extendedKeyUsage=serverAuth -keyout "${work}/$n.key" -out "${work}/$n.crt" >/dev/null 2>&1
done
port=18981
serve() { # <cert name>
    [[ -n "${pid}" ]] && { kill "${pid}" 2>/dev/null; wait "${pid}" 2>/dev/null || true; }
    python3 - "${work}/$1.crt" "${work}/$1.key" "${port}" <<'PY' &
import http.server, json, ssl, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = json.dumps({"host": self.headers.get("Host")}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", int(sys.argv[3])), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(sys.argv[1], sys.argv[2])
s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()
PY
    pid=$!
    for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null && return 0; sleep 0.1; done
    echo "fixture did not start" >&2; exit 1
}
serve loop
php "${here}/peer-name.php" "${work}/loop.crt" "${port}" loop
serve other
php "${here}/peer-name.php" "${work}/loop.crt" "${port}" other
mkdir "${work}/capath"; cp "${work}/other.crt" "${work}/capath/$(openssl x509 -hash -noout -in "${work}/other.crt").0"
php -d openssl.capath="${work}/capath" "${here}/peer-name.php" "${work}/loop.crt" "${port}" other
