# webmail-1.6.19-shcp.1 source lock — review notes

APPROVED by the release authority (owner) on 2026-10-01; every `review` field records it.

Sources are GitHub archive tarballs pinned to resolved commit SHAs (never tags); notices are the
upstream license file at the same commit, or the grant-bearing file where upstream ships none.
Fetch with `url`, verify with `sha256`, keep the exact `file` name. With reviews stubbed, the
audit accepts all 48 components. Every expression is GPL-3.0-compatible (24 MIT, 7 BSD-2-Clause,
6 BSD-3-Clause, 1 Apache-2.0, and GPL/LGPL grants listed below).

## Licence decisions — resolved

The owner accepted all three recommendations on 2026-09-30. They were implemented in #7 and are
declared in `distribution/inputs.json` with reason, upstream reference and removal condition.
Assembly, the source audit and CI all refuse a payload where one of them regresses. No upstream
issues were filed, by owner decision.

1. **pear/net_socket**: substituted with **v1.2.1, BSD-2-Clause** (`f31d75ac`). Upstream's
   `v1.2.2` tag points at 2015 code (`bbe6a12b`) under the PHP License 2.02, which is older than
   v1.2.1 (2017-04-06). Composer picks it only because the version number is higher. Both
   authors relicensed the code to BSD-2-Clause in `34b215d5` (PEAR bug 17526). v1.2.1 is the
   newer code: it adds PHP5 compatibility, bug #21031 and the 30s-timeout fix. Its one
   dependency, `pear/pear_exception`, is already in the payload.
2. **roundcube/rtf-html-php**: **omitted**. It is GPL-2.0-only (GPLv2 text, `composer.json`
   `GPL-2.0`, no "or later" grant in any file), which cannot combine with GPL-3.0 Roundcube.
   `henck/rtf-html-php` became MIT in `8e92b5e0` (2025-05-14), but Roundcube's 2020 fork, which
   carries 37 commits by Aleksander Machniak, did not follow. The TNEF decoder guards the call
   with `class_exists()` (`rcube_tnef_decoder.php:171-194`), so RTF bodies inside winmail.dat
   are not rendered and attachments still extract.
3. **TinyMCE community language packs**: **omitted**. They have no licence anywhere: none in
   `jsdeps.json`, none in the zip, and Tiny never answered tinymce/tinymce#6470. Transifex's
   terms leave ownership with the translators. Roundcube falls back to the built-in `en`
   (`rcmail_action.php:388-397`). Editor translations can be added later as SHCP-owned files.

## Settled by reading the grant

| Component | Expression | Evidence |
|---|---|---|
| asset/openpgp@5.0.0 | LGPL-3.0-or-later | `src/openpgp.js`: "version 3.0 … or (at your option) any later version" |
| asset/tinymce@5.10.9 | LGPL-2.1-only | headers: "Licensed under the LGPL"; LICENSE.TXT v2.1; no or-later grant |
| asset/publickey@0e011cb1 | GPL-3.0-only | GPLv3 LICENSE; `publickey.js` has no header or or-later grant |
| pear/crypt_gpg@v1.6.11 | LGPL-2.1-or-later | `Crypt/GPG.php`: "version 2.1 … or (at your option) any later version" |
| pear/net_ldap2@v2.3.0 | LGPL-3.0-only | `Net/LDAP2.php` `@license` LGPLv3; no or-later grant |
| pear/auth_sasl@v1.1.0 | BSD-3-Clause | `Auth/SASL.php` header: 3 clauses incl. no-endorsement |
| kolab/net_ldap3@v1.1.5 | GPL-3.0-or-later | `lib/Net/LDAP3.php`: "version 3 … or (at your option) any later version" |

## Provenance notes

- **kolab/net_ldap3**: Phabricator publishes no release tarball, and GitHub runners cannot
  always reach `git.kolab.org`. The source is `git archive 5a319cf4… | gzip -9n` of the pinned
  commit, and `url` points at the git repository rather than a downloadable file. Our source
  archive is therefore the only durable copy of those bytes.
- **asset/jstz@1.0.7**: upstream has no tags. The source is cdnjs's unminified `jstz.js` 1.0.7;
  the notice is from upstream HEAD.
- **PEAR packages and roundcube/plugin-installer** ship no license file. The notice is the
  grant-bearing file at the pinned commit (`Auth/SASL.php`, `Console/CommandLine.php`,
  `Mail/mime.php`, `Sieve.php`, `src/PEAR.php`, `composer.json`, `PluginInstaller.php`).
- **pear/net_socket@v1.2.1**: the notice is the upstream `LICENSE` added by the relicensing
  commit.
- **shcp/\***: the source is pinned to the release tag `webmail-1.6.19-shcp.1` (`98336b69`).

All remaining components map cleanly: the declared license is an unambiguous SPDX id and the
notice is the upstream license file.
