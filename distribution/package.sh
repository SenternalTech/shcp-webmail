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
# Public PR CI has no release signing key and cannot pass this gate.
gpgv --status-fd 1 --keyring /usr/share/keyrings/shcp-release-keyring.gpg \
    "$signature" "$assembled/payload-manifest.json" >"$scratch/signature-status"
grep -qE '^\[GNUPG:\] VALIDSIG .* 3DE2B72158369817363C9377AC582BC7BEBB2645$' "$scratch/signature-status"
php "$here/verify-payload.php" "$assembled/payload" "$assembled/payload-manifest.json"
cp -a "$assembled/payload" "$stage/usr/share/shcp-webmail/payload"
install -m 0644 "$assembled/payload-manifest.json" "$stage/usr/share/shcp-webmail/payload-manifest.json"
install -m 0644 "$signature" "$stage/usr/share/shcp-webmail/payload-manifest.json.asc"
install -m 0644 "$scratch/source-inventory.json" "$stage/usr/share/shcp-webmail/source-inventory.json"
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
# Exclusive publication within the local output directory; never replace a
# previously built version. This does not upload or publish a repository.
staged=$(mktemp "$output/.candidate.XXXXXX")
cp "$scratch/$artifact" "$staged"
if ! ln "$staged" "$output/$artifact"; then rm -f "$staged"; exit 1; fi
rm -f "$staged"
sha256sum "$output/$artifact"
