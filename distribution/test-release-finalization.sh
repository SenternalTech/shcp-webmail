#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d -t webmail-finalize.XXXXXX)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/release" "$work/bin"
release=webmail-1.6.19-shcp.1
source_name="$release-source.tar.gz"
deb=shcp-webmail_1.6.19+shcp.1_all.deb
rpm=shcp-webmail-1.6.19-1.shcp.noarch.rpm
printf source >"$work/release/$source_name"
printf deb >"$work/release/$deb"
printf rpm >"$work/release/$rpm"
source_sha="$(sha256sum "$work/release/$source_name" | awk '{print $1}')"
cat >"$work/release/$release-release-set.base.json" <<EOF
{"format":1,"release_id":"$release","package_name":"shcp-webmail","version":"1.6.19","revision":1,"source_date_epoch":1789776000,"source":{"url":"https://repo.shcp.dev/sources/shcp-webmail/$release/$source_name","filename":"$source_name","sha256":"$source_sha","size":6},"payload_manifest_sha256":"$(printf a%.0s {1..64})","source_inventory_sha256":"$(printf b%.0s {1..64})","source_lock_sha256":"$(printf c%.0s {1..64})","git_commit":"$(printf d%.0s {1..40})","packages":[]}
EOF
cat >"$work/bin/dpkg-deb" <<'EOF'
#!/bin/sh
case "$3" in
  Version) printf 1.6.19+shcp.1 ;;
  Architecture) printf all ;;
  *) exit 1 ;;
esac
EOF
cat >"$work/bin/rpm" <<'EOF'
#!/bin/sh
case "$*" in
  *VERSION*) printf 1.6.19-1.shcp ;;
  *ARCH*) printf noarch ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$work/bin/dpkg-deb" "$work/bin/rpm"
PATH="$work/bin:$PATH" php "$here/finalize-release.php" "$work/release" --output "$work/release/$release-release-set.json"
jq -e --arg deb "$deb" --arg rpm "$rpm" '
  [.packages[].format] == ["deb","rpm"] and
  [.packages[].filename] == [$deb,$rpm] and
  (all(.packages[]; (.sha256 | test("^[a-f0-9]{64}$")) and (.size > 0)))
' "$work/release/$release-release-set.json" >/dev/null
[[ "$(jq -r '.packages[0].sha256' "$work/release/$release-release-set.json")" == "$(sha256sum "$work/release/$deb" | awk '{print $1}')" ]]
[[ "$(jq -r '.packages[1].sha256' "$work/release/$release-release-set.json")" == "$(sha256sum "$work/release/$rpm" | awk '{print $1}')" ]]

rm "$work/release/$release-release-set.json" "$work/release/$rpm"
if PATH="$work/bin:$PATH" php "$here/finalize-release.php" "$work/release" --output "$work/release/$release-release-set.json" >/dev/null 2>&1; then
    echo 'FAIL: partial native release accepted' >&2
    exit 1
fi
printf 'PASS producer finalizer binds both exact native packages\n'
