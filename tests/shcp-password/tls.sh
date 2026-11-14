#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# shcp_password's TLS options: with shcp_password_cafile set, the panel call verifies
# that one anchor by IP (or by shcp_password_peer_name); another certificate for the
# same names is refused; a set-but-unusable setting fails closed; unset keeps the
# historical unverified call. A local TLS fixture on 127.0.0.1 stands in for the panel.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"; pid=""
trap '[[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null; rm -rf -- "${work}"' EXIT
for n in panel other; do
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 -subj "/CN=$n" \
        -addext 'subjectAltName=IP:127.0.0.1,IP:::1,DNS:shcpd.loopback.invalid' -addext extendedKeyUsage=serverAuth \
        -keyout "${work}/$n.key" -out "${work}/$n.crt" >/dev/null 2>&1
done
port=18982
serve() {
    [[ -n "${pid}" ]] && { kill "${pid}" 2>/dev/null; wait "${pid}" 2>/dev/null || true; }
    openssl s_server -accept "127.0.0.1:${port}" -cert "${work}/$1.crt" -key "${work}/$1.key" -www -quiet >/dev/null 2>&1 &
    pid=$!
    for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null && return 0; sleep 0.1; done
    echo "fixture did not start" >&2; exit 1
}
serve panel; php "${here}/tls.php" "${work}/panel.crt" "${port}" panel
serve other; php "${here}/tls.php" "${work}/panel.crt" "${port}" other
mkdir "${work}/capath"; cp "${work}/other.crt" "${work}/capath/$(openssl x509 -hash -noout -in "${work}/other.crt").0"
php -d openssl.capath="${work}/capath" "${here}/tls.php" "${work}/panel.crt" "${port}" other
