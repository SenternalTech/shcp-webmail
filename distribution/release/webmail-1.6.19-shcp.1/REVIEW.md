# webmail-1.6.19-shcp.1 source lock — review notes

DRAFT. Every `review` field in `source-lock.json` is empty on purpose: `source-audit.php`
refuses the lock until the release authority fills them in. Nothing here is signed or published.

Sources are GitHub archive tarballs pinned to resolved commit SHAs (never tags); notices are the
upstream license file at the same commit, or the grant-bearing file where upstream ships none.
Fetch with `url`, verify with `sha256`, keep the exact `file` name. With reviews stubbed and a
placeholder notice for tinymce-langs, the audit accepts all 50 components.

## Owner decisions

### 1. pear/net_socket@v1.2.2 — PHP License 2.02

`v1.2.2` is a mis-tag. It points at `bbe6a12b` (2015-03-22), older than `v1.2.1` (`f31d75ac`,
2017-04-06). Composer picks the higher version number, so every Roundcube install gets the stale
2015 code, which carries the PHP License 2.02 header. Upstream relicensed to BSD-2-Clause in
`34b215d5` (2017-03-24, "Both authors have agreed", PEAR bug 17526). `v1.2.1` is BSD-2-Clause
according to both its `composer.json` and Packagist. Neither pear/Net_Socket nor Roundcube has an
issue open about this.

The PHP License is GPL-incompatible per the FSF, and PHP-2.02 is outside the root CLAUDE.md
allowlist, which names PHP-3.01 only.

Options:
- **a. Substitute `v1.2.1` (BSD-2-Clause) at assembly.** This is a payload patch, so under the
  webmail exception it needs an upstream reference, reason, test and removal condition. The
  removal condition is "upstream tags a release above v1.2.2 from master". v1.2.1 is newer code:
  it is PHP5-compatible and carries bug #21031 and the 30s-timeout fix.
- b. Ship v1.2.2 and rely on the authors' relicensing statement. Weak, because the grant is
  attached to a later commit.
- c. Ship as upstream Roundcube does and accept PHP-2.02.

Recommendation: **a**, plus an upstream issue asking pear/Net_Socket to tag master.

### 2. roundcube/rtf-html-php@v2.2 — GPL-2.0-only

The code carries the GPLv2 text and `composer.json` says `GPL-2.0`. No file contains an
"or later" grant, and GPL-2.0-only cannot be combined with GPL-3.0 Roundcube in one program.
Roundcube forked `henck/rtf-html-php` in 2020 (merge base `2c632d35`) and added 37 commits by
Aleksander Machniak. `henck` relicensed its upstream to MIT on 2025-05-14 (`8e92b5e0`), but the
fork is still `GPL-2.0`, and Roundcube `master`/`release-1.7` still require `^2.1`.

The dependency is optional at runtime. `rcube_tnef_decoder.php:171-194` guards the call with
`class_exists('RtfHtmlPhp\Document')` and otherwise sets the body to `null`. The only loss is
that RTF bodies inside TNEF (winmail.dat) are not rendered; attachments still extract.

Options:
- **a. Omit it from the payload.** Drop `vendor/roundcube/rtf-html-php` and its
  `installed.json` entry. The autoload map can stay, because PSR-4 misses are a clean `false`.
- b. Ask Roundcube to relicense the fork to MIT, following `henck`, or to GPL-2.0-or-later.
  This needs Machniak's agreement.
- c. Ship as upstream Roundcube does.

Recommendation: **a** now, and **b** in parallel. Restore the component when upstream relicenses.

### 3. asset/tinymce-langs@5.10.9 — no license anywhere

There is no license in `jsdeps.json`, none in the zip, and no public upstream repository. Tiny
was asked this exact question in tinymce/tinymce#6470 ("Are the language packages also licensed
under LGPL-2.1?"). Tiny said it would ask its legal team, never answered, and the stale bot
closed the issue. The packs are community Transifex translations. Transifex's terms leave
ownership with the translators and grant a licence only to Transifex, not to downstream users.

Roundcube needs none of them to work: `rcmail_action.php:388-397` falls back to the built-in
`en` when `program/js/tinymce/langs/<code>.js` is absent. The cost is an English editor toolbar
for non-English users. The rest of the Roundcube UI stays localized.

Options:
- **a. Omit the packs from the payload.** Drop `program/js/tinymce/langs/` and remove the
  component from `jsdeps.json` handling.
- b. Ship on an implied-licence reading (translations contributed to an LGPL project for use
  with it). This cannot be written down as a license expression.

Recommendation: **a**.

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
  commit, so our source archive is the only durable copy of those bytes.
- **asset/jstz@1.0.7**: upstream has no tags. The source is cdnjs's unminified `jstz.js` 1.0.7;
  the notice is from upstream HEAD.
- **PEAR packages and roundcube/plugin-installer** ship no license file. The notice is the
  grant-bearing file at the pinned commit (`Auth/SASL.php`, `Console/CommandLine.php`,
  `Mail/mime.php`, `Sieve.php`, `Net/Socket.php`, `src/PEAR.php`, `composer.json`,
  `PluginInstaller.php`).
- **shcp/\***: the source is pinned to shcp-webmail `main` at `9eaf0f11`. Re-pin it to the
  release tag commit.

All remaining components map cleanly: the declared license is an unambiguous SPDX id and the
notice is the upstream license file.
