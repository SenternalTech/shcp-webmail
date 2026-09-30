# webmail-1.6.19-shcp.1 source lock — review notes

DRAFT. Every `review` field is empty on purpose: `source-audit.php` refuses the lock until
the release authority fills them in. Nothing here is signed or published.

Sources: GitHub archive tarballs pinned to resolved commit SHAs (never tags); notices are the
upstream license file at the same commit. Fetch with `url`, verify with `sha256`, keep the
exact `file` name. Dry run with reviews stubbed and a tinymce-langs placeholder: audit
accepts all 50 components.

## Owner decisions

- **asset/tinymce-langs@5.10.9** — no license declared in jsdeps.json, none in the zip, no public upstream repo; notice absent
- **pear/net_socket@v1.2.2** — PHP License 2.02 (header of Net/Socket.php). FSF classes the PHP License GPL-incompatible; CLAUDE.md allow-list names PHP-3.01 only. Roundcube upstream bundles it.
- **roundcube/rtf-html-php@v2.2** — GPLv2 text, composer GPL-2.0, no "or later" grant in any file. GPL-2.0-only cannot combine with GPL-3.0 Roundcube. Optional at runtime (class_exists guard, rcube_tnef_decoder.php:174): omitting it from the payload removes the conflict, costing RTF rendering of TNEF bodies

## Confirm on review

- **asset/jstz@1.0.7** — upstream has no tags; source is cdnjs unminified jstz.js 1.0.7, notice from upstream HEAD
- **asset/openpgp@5.0.0** — declared license 'LGPL' is ambiguous; license_expression must be read from the notice; notice is LGPLv3 text; "or later" from upstream package.json LGPL-3.0+ - confirm
- **asset/publickey@0e011cb1** — declared license 'GPLv3' is ambiguous; license_expression must be read from the notice; notice is GPLv3 text; no "or later" grant found - taken as only
- **asset/tinymce@5.10.9** — declared license 'LGPL' is ambiguous; license_expression must be read from the notice; notice is LGPLv2.1 text; no "or later" grant checked - confirm
- **kolab/net_ldap3@v1.1.5** — Phabricator has no release tarball; source is `git archive 5a319cf437d75aad564ce7fd076cc5423722868b | gzip -9n` of https://git.kolab.org/diffusion/PNL/php-net_ldap3.git; notice extracted from it
- **pear/auth_sasl@v1.1.0** — declared license 'BSD' is ambiguous; license_expression must be read from the notice; upstream ships no license file; notice is the grant-bearing Auth/SASL.php at the pinned commit; three-clause BSD text in Auth/SASL.php header - confirm clause count
- **pear/console_commandline@v1.2.6** — upstream ships no license file; notice is the grant-bearing Console/CommandLine.php at the pinned commit
- **pear/crypt_gpg@v1.6.11** — declared license 'LGPL-2.1' is ambiguous; license_expression must be read from the notice; notice is LGPLv2.1 text; composer LGPL-2.1 = only - confirm
- **pear/mail_mime@1.10.13** — upstream ships no license file; notice is the grant-bearing Mail/mime.php at the pinned commit
- **pear/net_ldap2@v2.3.0** — declared license 'LGPL-3.0' is ambiguous; license_expression must be read from the notice; notice is LGPLv3 text; composer LGPL-3.0 = only
- **pear/net_sieve@1.4.8** — upstream ships no license file; notice is the grant-bearing Sieve.php at the pinned commit
- **pear/pear-core-minimal@v1.10.18** — upstream ships no license file; notice is the grant-bearing src/PEAR.php at the pinned commit
- **roundcube/plugin-installer@0.3.11** — upstream ships no license file; notice is the grant-bearing composer.json at the pinned commit
- **roundcube/plugin-installer@0.3.2** — upstream ships no license file; notice is the grant-bearing src/Roundcube/Composer/PluginInstaller.php at the pinned commit
- **shcp/shcp_dav@1** — source pinned to shcp-webmail main cb6a411ac13953d33bd8aaf5979b644c17ce4ea4; re-pin to the release tag commit
- **shcp/shcp_password@1** — source pinned to shcp-webmail main cb6a411ac13953d33bd8aaf5979b644c17ce4ea4; re-pin to the release tag commit
- **shcp/shcp_sso@1** — source pinned to shcp-webmail main cb6a411ac13953d33bd8aaf5979b644c17ce4ea4; re-pin to the release tag commit

Remaining components map cleanly: declared licence is an unambiguous SPDX id and the
notice is the upstream license file.
