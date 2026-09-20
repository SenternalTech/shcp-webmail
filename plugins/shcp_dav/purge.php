<?php
// SPDX-License-Identifier: MIT
// Supported managed-cache purge, run before an administrative user deletion that does not go through
// bin/deluser.sh. Caller owns the rollback snapshot. Resumable: re-run after an interrupted run.
// Usage: php plugins/shcp_dav/purge.php <user_id|username>
if (PHP_SAPI !== 'cli') { http_response_code(404); exit(1); }
define('INSTALL_PATH',dirname(__DIR__,2).'/');
require INSTALL_PATH.'program/include/iniset.php';
require __DIR__.'/lib/Bindings.php';
try {
    $subject=trim((string)($argv[1]??''));
    if ($subject==='') throw new RuntimeException('Usage: purge.php <user_id|username>');
    $rc=rcube::get_instance(rcube::INIT_WITH_DB);
    $prefix=(string)$rc->config->get('db_prefix','');
    if (!preg_match('/\A[a-zA-Z0-9_]*\z/',$prefix)) throw new RuntimeException('Invalid database prefix');
    $dsn=$rc->config->get('db_dsnw');
    if (!is_string($dsn) || !str_starts_with($dsn,'sqlite:') || str_contains($dsn,'?')) throw new RuntimeException('SQLite configuration required');
    $db=new PDO($dsn);
    $db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
    if (ctype_digit($subject)) $user=(int)$subject;
    else {
        // A username is not unique on its own: refuse rather than guess which mail host was meant.
        $q=$db->prepare("SELECT user_id FROM {$prefix}users WHERE username=?");$q->execute([$subject]);
        $rows=$q->fetchAll(PDO::FETCH_COLUMN);
        if (count($rows)!==1) throw new RuntimeException('Username did not resolve to exactly one user');
        $user=(int)$rows[0];
    }
    $accounts=(new \Shcp\Webmail\Dav\Bindings($db,$prefix))->purge($user);
    fwrite(STDOUT,"SHCP_DAV_PURGE_OK=$accounts\n");
} catch (Throwable $e) {
    // Deliberately no exception/body logging: database errors can quote row contents.
    fwrite(STDERR,"SHCP DAV managed cache purge failed\n");
    exit(1);
}
