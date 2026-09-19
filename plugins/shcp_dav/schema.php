<?php
// SPDX-License-Identifier: MIT
// Deployment-only migration entry point. Caller owns webmail quiescence and rollback snapshot.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit(1); }
define('INSTALL_PATH',dirname(__DIR__,2).'/');
require INSTALL_PATH.'program/include/iniset.php';
require __DIR__.'/lib/Bindings.php';
try {
    $rc=rcube::get_instance(rcube::INIT_WITH_DB);
    require INSTALL_PATH.'plugins/carddav/vendor/autoload.php';
    $infra=\MStilkerich\RCMCardDAV\Config::inst();
    $prefix=(string)$rc->config->get('db_prefix','');
    $infra->db()->checkMigrations($prefix,INSTALL_PATH.'plugins/carddav/dbmigrations/');
    $dsn=$rc->config->get('db_dsnw');
    if (!is_string($dsn) || !str_starts_with($dsn,'sqlite:') || str_contains($dsn,'?')) throw new RuntimeException('SQLite configuration required');
    (new \Shcp\Webmail\Dav\Bindings(new PDO($dsn),$prefix))->install();
    fwrite(STDOUT,"SHCP_DAV_SCHEMA_OK=1\n");
} catch (Throwable $e) {
    fwrite(STDERR,"SHCP DAV schema migration failed\n");
    exit(1);
}