<?php
// SPDX-License-Identifier: MIT
// Usage: php tests/shcp-dav/userdelete.php /path/to/assembled/roundcube /path/to/extracted/carddav
//
// Proves the user_delete_prepare hook wiring in shcp_dav.php against an assembled Roundcube runtime.
// bin/deluser.sh (the only place a Roundcube user is removed) fires a hook before it deletes the row;
// shcp_dav must handle it, purge the managed DAV cache and raise the reissue fence, so the deletion
// can proceed. With the add_hook('user_delete_prepare', ...) registration removed, the purge never
// runs, the shcp_dav_user_delete guard aborts the row removal, and this test exits non-zero.
//
// The hook name is read from bin/deluser.sh itself, never hardcoded here, so a plugin that wired the
// wrong hook cannot pass this test either. Every check runs under an explicit try/catch: Roundcube's
// boot installs an exception handler that would otherwise turn an assertion failure into a fatal that
// exits zero, so we catch first and set the exit code ourselves.

function need(bool $ok, string $why): void { if (!$ok) throw new RuntimeException($why); }

try {
    ob_start();
    $rcRoot  = rtrim($argv[1] ?? '', '/');
    $carddav = rtrim($argv[2] ?? '', '/');
    need($rcRoot !== '' && $carddav !== '', 'usage: userdelete.php <roundcube-root> <carddav-dir>');
    define('INSTALL_PATH', $rcRoot.'/');
    $_SERVER['REMOTE_ADDR'] = '127.0.0.1';

    $work = sys_get_temp_dir().'/shcp-dav-userdelete-'.bin2hex(random_bytes(6));
    mkdir($work, 0700);
    $dbfile = $work.'/roundcube.sqlite';
    $dsn    = 'sqlite:'.$dbfile; // A plain PDO DSN: shcp_dav opens its own PDO from db_dsnw, never rcube's handle.

    // Minimal CLI configuration for the assembled tree. rcube boots for the plugin API only; the managed
    // cache lives in $dsn, which shcp_dav reads back from db_dsnw.
    file_put_contents($rcRoot.'/config/config.inc.php',
        "<?php\n\$config = [];\n"
        ."\$config['db_dsnw'] = ".var_export($dsn, true).";\n"
        ."\$config['des_key'] = '0123456789abcdef0123456789ABCD';\n"
        ."\$config['plugins'] = [];\n"
        ."\$config['enable_installer'] = false;\n"
    );

    require INSTALL_PATH.'program/include/iniset.php';

    // Seed the database the way a deployed managed cache looks: the real Roundcube schema, the pinned
    // rcmcarddav schema, and one live managed generation for the user we are about to delete.
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec(file_get_contents(INSTALL_PATH.'SQL/sqlite.initial.sql'));
    $pdo->exec(str_replace('TABLE_PREFIX', '', file_get_contents($carddav.'/dbmigrations/INIT-currentschema/sqlite3.sql')));
    $pdo->exec("INSERT INTO users(user_id,username,mail_host,created,language,preferences) VALUES(1,'alice@example.test','localhost',datetime('now'),'en_US','a:0:{}')");

    require dirname(__DIR__, 2).'/plugins/shcp_dav/lib/Bindings.php';
    $binding = str_repeat('a', 32);
    $store   = new \Shcp\Webmail\Dav\Bindings($pdo);
    $store->install();
    $account = $store->activate(1, 'shcp', $binding, 'alice@example.test', 'https://panel.example.test');
    $pdo->exec("INSERT INTO carddav_addressbooks(name,url,account_id) VALUES('Live','https://panel.example.test/dav/live',$account)");
    $book = (int) $pdo->lastInsertId();
    $pdo->exec("INSERT INTO carddav_contacts(abook_id,name,vcard,etag,uri,cuid) VALUES($book,'Live Person','live-card','live-etag','live.vcf','live-uid')");
    need($store->current(1, $account, $binding), 'seed: managed generation is not active');

    // Boot the real plugin API and load the product plugin so init() registers its hooks on it.
    $rc = rcube::get_instance(rcube::INIT_WITH_PLUGINS);
    require dirname(__DIR__, 2).'/plugins/shcp_dav/shcp_dav.php';
    $bridge = new shcp_dav($rc->plugins);
    $bridge->init();

    // Take the pre-deletion hook name from bin/deluser.sh: the real firing site fires it with a 'user'
    // array literal before it removes the row. Deriving it here means the plugin must wire the same hook.
    $deluser   = file_get_contents(INSTALL_PATH.'bin/deluser.sh');
    $preDelete = substr($deluser, 0, (int) strpos($deluser, 'DELETE FROM'));
    need(preg_match("/exec_hook\\(\\s*'([a-z_]+)'\\s*,\\s*\\[\\s*'user'\\s*=>/", $preDelete, $m) === 1,
        'bin/deluser.sh no longer fires a pre-delete hook with a user argument');
    $hook = $m[1];
    need(!empty($rc->plugins->handlers[$hook]),
        "shcp_dav did not register a handler for the '$hook' hook that bin/deluser.sh fires");

    // Fire the hook exactly as bin/deluser.sh does (same argument shape), through the real plugin API.
    $user = new rcube_user(1, ['user_id' => 1, 'username' => 'alice@example.test', 'mail_host' => 'localhost', 'language' => 'en_US']);
    need((int) $user->ID === 1, 'fixture user identity');
    $result = $rc->plugins->exec_hook($hook, ['user' => $user, 'username' => 'alice@example.test', 'host' => 'localhost']);
    need(empty($result['abort']), 'the hook aborted the deletion of a user whose managed cache is present and purgeable');

    // Expected managed-DAV cleanup and reissue fencing.
    need((int) $pdo->query('SELECT COUNT(*) FROM shcp_dav_bindings WHERE user_id=1')->fetchColumn() === 0, 'hook did not purge the binding rows');
    need((int) $pdo->query("SELECT COUNT(*) FROM carddav_accounts WHERE id=$account")->fetchColumn() === 0, 'hook did not remove the managed account');
    need((int) $pdo->query('SELECT COUNT(*) FROM carddav_addressbooks')->fetchColumn() === 0, 'hook did not remove the cached book');
    need((int) $pdo->query('SELECT COUNT(*) FROM carddav_contacts')->fetchColumn() === 0, 'hook did not remove the cached contacts');
    need((int) $pdo->query('SELECT COUNT(*) FROM shcp_dav_cleanup')->fetchColumn() === 0, 'hook left the cleanup journal open');
    need((int) $pdo->query("SELECT high FROM shcp_dav_idfloor WHERE scope='account'")->fetchColumn() >= $account, 'hook did not raise the account identifier floor');

    // bin/deluser.sh's next step is DELETE FROM users; it must now succeed, i.e. the shcp_dav_user_delete
    // guard is satisfied by the hook-driven cleanup. Without the wiring this row removal aborts.
    $pdo->exec('DELETE FROM users WHERE user_id=1');
    need((int) $pdo->query('SELECT COUNT(*) FROM users WHERE user_id=1')->fetchColumn() === 0, 'user remained undeletable after the hook cleanup');

    ob_end_clean();
    echo "PASS user_delete_prepare hook purges the managed DAV cache and fences identifier reissue\n";
    echo "PASS Roundcube user deletion proceeds once the hook has run\n";
    echo "SHCP_DAV_USERDELETE_OK\n";
    exit(0);
} catch (Throwable $e) {
    if (ob_get_level() > 0) { ob_end_clean(); }
    fwrite(STDERR, 'FAIL: '.$e->getMessage()."\n");
    exit(1);
}
