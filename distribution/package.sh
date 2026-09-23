#!/usr/bin/env bash
# Inert all/noarch payload. No maintainer script, trigger, service or migration.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ $EUID != 0 && $# == 6 ]] || { echo 'usage (unprivileged): package.sh deb|rpm ASSEMBLED SOURCE_LOCK SOURCES MANIFEST_SIGNATURE OUTPUT' >&2; exit 2; }
format=$1 assembled=$(realpath "$2") source_lock=$(realpath "$3") sources=$(realpath "$4") signature=$(realpath "$5") output=$(realpath -m "$6")
[[ "$format" == deb || "$format" == rpm ]] || exit 2
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
umask 022
stage="$scratch/stage"
mkdir -p "$stage/usr/share/shcp-webmail" "$stage/usr/share/doc/shcp-webmail" "$output"
php "$here/source-audit.php" "$assembled/payload" "$source_lock" "$sources" "$scratch/source-inventory.json"
release_id=$(jq -er '.release_id' "$here/inputs.json")
source_filename="${release_id}-source.tar.gz"
if [[ -n "${SHCP_EXISTING_SOURCE_ARCHIVE:-}" || -n "${SHCP_EXISTING_SOURCE_LOCATOR:-}" || -n "${SHCP_EXISTING_SOURCE_ROOT:-}" ]]; then
    [[ -n "${SHCP_EXISTING_SOURCE_ARCHIVE:-}" && -n "${SHCP_EXISTING_SOURCE_LOCATOR:-}" && -n "${SHCP_EXISTING_SOURCE_ROOT:-}" ]] || { echo 'all existing-source inputs are required' >&2; exit 1; }
    existing_source=$(realpath "$SHCP_EXISTING_SOURCE_ARCHIVE")
    existing_locator=$(realpath "$SHCP_EXISTING_SOURCE_LOCATOR")
    existing_root=$(realpath "$SHCP_EXISTING_SOURCE_ROOT")
    [[ -f "$existing_source" && ! -L "$SHCP_EXISTING_SOURCE_ARCHIVE" && -f "$existing_locator" && ! -L "$SHCP_EXISTING_SOURCE_LOCATOR" && -d "$existing_root" && ! -L "$SHCP_EXISTING_SOURCE_ROOT" ]] || exit 1
    [[ "$(basename "$existing_source")" == "$source_filename" ]] || exit 1
    cp "$existing_source" "$scratch/$source_filename"
    cp "$existing_locator" "$scratch/release-set.json"
    php -r 'require $argv[1]; $d=wm_json($argv[2]); wm_validate_locator($d); $r=$argv[4]; if ($d["packages"] !== [] || hash_file("sha256", $argv[3]) !== $d["source"]["sha256"] || filesize($argv[3]) !== $d["source"]["size"] || hash_file("sha256", "$r/assembled/payload-manifest.json") !== $d["payload_manifest_sha256"] || hash_file("sha256", "$r/source-inventory.json") !== $d["source_inventory_sha256"] || hash_file("sha256", "$r/source-lock.json") !== $d["source_lock_sha256"]) throw new RuntimeException("invalid existing source binding");' "$here/corresponding-source.php" "$scratch/release-set.json" "$scratch/$source_filename" "$existing_root"
else
    php "$here/corresponding-source.php" "$assembled" "$source_lock" "$sources" "$signature" --output "$scratch/$source_filename" >"$scratch/release-set.json"
fi
jq -e --arg release_id "$release_id" --arg filename "$source_filename" '
  .format == 1 and .release_id == $release_id and .package_name == "shcp-webmail" and
  .source.filename == $filename and .source.url == ("https://repo.shcp.dev/sources/shcp-webmail/" + $release_id + "/" + $filename) and
  (.source.sha256 | test("^[a-f0-9]{64}$")) and (.source.size | type == "number" and . > 0)
' "$scratch/release-set.json" >/dev/null
# Public PR CI has no release signing key and cannot pass this gate.
gpgv --status-fd 1 --keyring /usr/share/keyrings/shcp-release-keyring.gpg \
    "$signature" "$assembled/payload-manifest.json" >"$scratch/signature-status"
grep -qE '^\[GNUPG:\] VALIDSIG .* 3DE2B72158369817363C9377AC582BC7BEBB2645$' "$scratch/signature-status"
php "$here/verify-payload.php" "$assembled/payload" "$assembled/payload-manifest.json"
cp -a "$assembled/payload" "$stage/usr/share/shcp-webmail/payload"
install -m 0644 "$assembled/payload-manifest.json" "$stage/usr/share/shcp-webmail/payload-manifest.json"
install -m 0644 "$signature" "$stage/usr/share/shcp-webmail/payload-manifest.json.asc"
install -m 0644 "$scratch/source-inventory.json" "$stage/usr/share/shcp-webmail/source-inventory.json"
jq '{format, release_id, source}' "$scratch/release-set.json" >"$stage/usr/share/shcp-webmail/corresponding-source.json"
jq -r '"Corresponding source for " + .release_id + ":\n" + .source.url + "\nSHA-256: " + .source.sha256 + "\nSize: " + (.source.size | tostring) + " bytes"' \
    "$scratch/release-set.json" >"$stage/usr/share/doc/shcp-webmail/CORRESPONDING-SOURCE"
php "$here/notices.php" "$scratch/source-inventory.json" "$sources" >"$stage/usr/share/doc/shcp-webmail/copyright"
version=$(jq -er '.version' "$here/inputs.json")
revision=$(jq -er '.revision' "$here/inputs.json")
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$revision" =~ ^[1-9][0-9]*$ ]] || exit 1
export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH=$(jq -er '.source_date_epoch' "$here/inputs.json")
find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
if [[ "$format" == deb ]]; then
    mkdir "$stage/DEBIAN"
    cat >"$stage/DEBIAN/control" <<EOF
Package: shcp-webmail
Version: ${version}+shcp.${revision}
Architecture: all
Section: web
Priority: optional
Maintainer: Senternal <support@senternal.com>
Description: SHCP webmail inactive distribution payload
 Activation and runtime dependencies are managed by SHCP.
EOF
    artifact="shcp-webmail_${version}+shcp.${revision}_all.deb"
    dpkg-deb --root-owner-group --build "$stage" "$scratch/$artifact"
else
    mkdir -p "$scratch/rpm/"{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
    cat >"$scratch/rpm/SPECS/shcp-webmail.spec" <<EOF
Name: shcp-webmail
Version: ${version}
Release: ${revision}.shcp
Summary: SHCP webmail inactive distribution payload
License: GPL-3.0-or-later AND MIT
BuildArch: noarch
AutoReqProv: no
%global debug_package %{nil}
%description
Inactive payload; activation is managed by SHCP.
%install
mkdir -p %{buildroot}
cp -a ${stage}/usr %{buildroot}/
%files
%defattr(-,root,root,-)
/usr/share/shcp-webmail
/usr/share/doc/shcp-webmail
EOF
    rpmbuild --define "_topdir $scratch/rpm" -bb "$scratch/rpm/SPECS/shcp-webmail.spec"
    artifact="shcp-webmail-${version}-${revision}.shcp.noarch.rpm"
    mv "$scratch/rpm/RPMS/noarch/$artifact" "$scratch/$artifact"
fi
# Source and release metadata are versioned outputs, but are common to both
# package formats. Publish them first; a second format must reproduce them
# byte-for-byte. This remains only a local output operation, not an upload.
for common in "$source_filename" "${release_id}-release-set.base.json"; do
    candidate="$scratch/$common"
    [[ "$common" == *-release-set.base.json ]] && candidate="$scratch/release-set.json"
    if [[ -e "$output/$common" ]]; then
        cmp -s "$candidate" "$output/$common" || { echo "conflicting release output: $common" >&2; exit 1; }
    else
        published=$(mktemp "$output/.candidate.XXXXXX")
        cp "$candidate" "$published"
        if ! ln "$published" "$output/$common"; then rm -f "$published"; exit 1; fi
        rm -f "$published"
    fi
done
# Exclusive package publication within the local output directory; never
# replace a previously built version.
staged=$(mktemp "$output/.candidate.XXXXXX")
cp "$scratch/$artifact" "$staged"
if ! ln "$staged" "$output/$artifact"; then rm -f "$staged"; exit 1; fi
rm -f "$staged"
sha256sum "$output/$artifact"
