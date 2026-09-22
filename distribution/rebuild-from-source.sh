#!/usr/bin/env bash
set -euo pipefail
[[ $EUID != 0 && $# == 3 ]] || { echo 'usage (unprivileged): rebuild-from-source.sh SOURCE_ARCHIVE EXTRACTED_RELEASE_ROOT OUTPUT' >&2; exit 2; }
archive=$(realpath "$1") root=$(realpath "$2") output=$(realpath -m "$3")
[[ -f "$archive" && ! -L "$1" && -d "$root" && ! -L "$2" ]] || { echo 'source inputs must be regular, resolved paths' >&2; exit 2; }
here="$root/distribution"
provenance="$root/archive-provenance.json"
[[ -f "$provenance" && ! -L "$provenance" ]] || { echo 'archive provenance is absent' >&2; exit 1; }
release_id=$(jq -er '.release_id | select(test("^webmail-[0-9]+\\.[0-9]+\\.[0-9]+-shcp\\.[1-9][0-9]*$"))' "$provenance")
[[ "$(basename "$root")" == "$release_id" && "$(basename "$archive")" == "$release_id-source.tar.gz" ]] || { echo 'source archive identity mismatch' >&2; exit 1; }
mkdir -p "$output"
locator=$(mktemp "$output/.source-locator.XXXXXX")
trap 'rm -f -- "$locator"' EXIT
jq -n --slurpfile p "$provenance" --arg filename "$(basename "$archive")" \
  --arg sha "$(sha256sum "$archive" | awk '{print $1}')" --argjson size "$(stat -f %z "$archive" 2>/dev/null || stat -c %s "$archive")" '
  $p[0] as $p | {format:1,release_id:$p.release_id,package_name:"shcp-webmail",
    version:$p.version,revision:$p.revision,source_date_epoch:$p.source_date_epoch,
    source:{url:("https://repo.shcp.dev/sources/shcp-webmail/"+$p.release_id+"/"+$filename),filename:$filename,sha256:$sha,size:$size},
    payload_manifest_sha256:$p.payload_manifest_sha256,source_inventory_sha256:$p.source_inventory_sha256,
    source_lock_sha256:$p.source_lock_sha256,git_commit:$p.git_commit,packages:[]}' >"$locator"
export SHCP_EXISTING_SOURCE_ARCHIVE="$archive" SHCP_EXISTING_SOURCE_LOCATOR="$locator" SHCP_EXISTING_SOURCE_ROOT="$root"
"$here/package.sh" deb "$root/assembled" "$root/source-lock.json" "$root/inputs" "$root/assembled/payload-manifest.json.asc" "$output"
"$here/package.sh" rpm "$root/assembled" "$root/source-lock.json" "$root/inputs" "$root/assembled/payload-manifest.json.asc" "$output"
php "$here/finalize-release.php" "$output" --output "$output/$release_id-release-set.json"
printf 'Rebuilt %s from complete corresponding source\n' "$release_id"
