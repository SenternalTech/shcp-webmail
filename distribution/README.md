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
5. Run `distribution/package.sh deb|rpm ASSEMBLED SOURCE_LOCK SOURCES SIGNATURE OUTPUT`.
   It checks the detached manifest signature and payload, generates notices,
   and builds an inert all/noarch package. It refuses to replace an existing
   output version. Package signing and repository promotion remain separate.

The package owns only `/usr/share/shcp-webmail/` and its documentation. It has
no activation script, service restart, database migration or runtime download.
The SHCP updater owns copying an authenticated release to the independent
release store, quiescence, migration, health checks and coherent rollback.

Host configuration belongs under `/etc/shcp-roundcube/`; credentials and
databases must never be added to this source tree. The deployment explicitly
loads `shcp_dav` before `carddav`. Calendar compatibility is not part of this
contacts release.

Run the build-boundary checks with `php distribution/test-distribution.php`.
Plugin tests live under `tests/shcp-dav/` and require the pinned assembled
Roundcube/CardDAV runtime, not an unrelated globally installed version.

Release readiness is not implied by a successful assembly. Complete source
classification, recipient rebuild, both native package formats, supported
runtime tests and signed release approval must all pass before promotion.
