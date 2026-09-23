# SHCP webmail distribution

This downstream retains Roundcube's upstream license and history. The SHCP
integration plugins have their own MIT grants. The panel is a separate service;
its proprietary source and deployment secrets are not part of this repository.

Build preparation uses PHP and Bash. It needs PHP 8.5 with Phar and the runtime
extensions in the payload manifest, Git, jq, GNU coreutils, and the selected
native packager (`dpkg-deb` or `rpmbuild`). Run builds as an unprivileged user.

1. Obtain the public archives identified in `inputs.json`, retaining their exact
   filenames. Verify upstream authenticity as part of release preparation.
2. Run `php distribution/assemble.php INPUT_DIRECTORY ABSOLUTE_OUTPUT_DIRECTORY`.
   This checks archive digests, applies the reviewed CardDAV patch series,
   installs the MIT plugins and protected external-config loaders, and emits a
   complete payload file manifest. Roundcube 1.6 routing is retained; its optional
   alternate `public_html` symlink tree and browser installer are omitted.
3. Audit every observed component with `source-audit.php`. A reviewed source lock,
   preferred editable source archives and their actual notices are mandatory.
   Missing/changed sources or unknown classifications fail the build.
4. The release authority reviews the complete corresponding source and signs
   the payload manifest. Public CI cannot perform this step.
5. Run `distribution/package.sh deb|rpm ASSEMBLED SOURCE_LOCK SOURCES SIGNATURE OUTPUT`
   once for each native format.
   It checks the detached manifest signature and payload, generates notices,
   creates the deterministic complete-source archive and canonical release-set
   metadata, and builds an inert all/noarch package. Both package formats embed
   `/usr/share/shcp-webmail/corresponding-source.json` and a human-readable
   source pointer. It refuses to replace an existing output version. After both
   producer package bytes exist, run
   `php distribution/finalize-release.php OUTPUT --output OUTPUT/webmail-X.Y.Z-shcp.N-release-set.json`.
   This is the only command that creates the producer release set; it inspects
   both native package identities and binds their exact handoff bytes. The
   consumer contract is that JSON, the two named packages, and the named source
   archive. The repository release authority subsequently signs the RPM and
   emits its final repository manifest with the signed RPM digest. This
   producer release set is not represented as a detached-signed final manifest.

The source artifact is named from the complete downstream release ID (for
example `webmail-1.6.19-shcp.1-source.tar.gz`). It contains the exact patched
assembled tree, payload manifest, audited preferred source and notice inputs,
source lock and inventory, SHCP plugin source, patches, and distribution build
recipes. Its release-set metadata fixes the immutable public URL under
`https://repo.shcp.dev/sources/shcp-webmail/`; packages contain no package
digest, avoiding a self-referential hash. Publication tooling adds native
producer package records are added only by the finalizer after both formats are
built.

Only clean, Git-tracked files under `distribution/` and the three SHCP plugin
directories are admitted as reviewed build recipes/plugin sources. A dirty or
untracked file in that scope aborts source generation, preventing editor files,
credentials, or other local material from entering the archive. Generated
payload, audit inventory, source lock, and audited upstream inputs are added
through their explicit paths.

The package owns only `/usr/share/shcp-webmail/` and its documentation. It has
no activation script, service restart, database migration or runtime download.
The SHCP updater owns copying an authenticated release to the independent
release store, quiescence, migration, health checks and coherent rollback.

Host configuration belongs under `/etc/shcp-roundcube/`; credentials and
databases must never be added to this source tree. The deployment explicitly
loads `shcp_dav` before `carddav`. Calendar compatibility is not part of this
contacts release.

Run the build-boundary checks with `php distribution/test-distribution.php` and
the producer/finalizer seam check with `distribution/test-release-finalization.sh`.
Recipients can extract the source archive and rebuild both formats without Git,
network access, or private material with
`distribution/rebuild-from-source.sh ORIGINAL_SOURCE_ARCHIVE EXTRACTED_RELEASE_ROOT OUTPUT`.
The rebuild verifies the archived payload signature, source audit, payload
manifest, archive identity and provenance, then uses the original archive as
the package source locator instead of recursively creating another archive.
The producer release set must also be distributed with a detached
`release-set.json.asc` signature from the release authority; signing that file
is an external release step and is intentionally not performed by these public
build recipes.
Plugin tests live under `tests/shcp-dav/` and require the pinned assembled
Roundcube/CardDAV runtime, not an unrelated globally installed version.

Release readiness is not implied by a successful assembly. Complete source
classification, recipient rebuild, both native package formats, supported
runtime tests and signed release approval must all pass before promotion.
